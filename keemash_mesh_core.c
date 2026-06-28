// SPDX-License-Identifier: GPL-2.0-only
#include "keemash_mesh_core.h"

#include <stdlib.h>
#include <string.h>

#include "esp_random.h"
#include "esp_timer.h"

#define KM_CHANNEL_COUNT	(MESH_V2_TUNNEL_CHANNEL_MAX + 1)
#define KM_PACKET_MAX		MESH_V2_PACKET_MAX
#define KM_MESSAGE_MAX		(MESH_V2_RELIABLE_INNER_MAX * MESH_V2_RELIABLE_MAX_FRAGMENTS)
#define KM_PENDING_LOST_RANGES	8

typedef struct {
	bool used;
	uint8_t peer[6];
	uint8_t channel;
	uint8_t priority;
	uint32_t seq;
	uint32_t stream_id;
	uint32_t first_sent_ms;
	uint32_t last_sent_ms;
	uint8_t retries;
	size_t len;
	uint8_t bytes[KM_PACKET_MAX];
} tx_slot_t;

typedef struct {
	bool used;
	uint8_t peer[6];
	uint8_t channel;
	uint32_t seq;
	mesh_v2_reliable_hdr_t hdr;
	uint16_t payload_len;
	uint8_t payload[MESH_V2_RELIABLE_INNER_MAX];
} rx_slot_t;

typedef struct {
	bool used;
	uint8_t peer[6];
	uint8_t channel;
	uint32_t stream_id;
	uint32_t first_seq;
	uint32_t last_ms;
	uint16_t fragment_len[MESH_V2_RELIABLE_MAX_FRAGMENTS];
	uint16_t received_mask;
	uint8_t fragment_count;
	uint8_t data[KM_MESSAGE_MAX];
} reassembly_slot_t;

typedef struct {
	bool used;
	uint8_t channel;
	uint32_t first;
	uint32_t last;
} pending_lost_range_t;

typedef struct {
	bool used;
	uint8_t mac[6];
	uint8_t remote_mac[6];
	bool ready;
	uint32_t root_session_id;
	uint32_t node_session_id;
	uint32_t next_seq[KM_CHANNEL_COUNT];
	uint32_t expected_seq[KM_CHANNEL_COUNT];
	pending_lost_range_t pending_lost[KM_PENDING_LOST_RANGES];
	uint32_t last_ack_ms;
	uint32_t last_rx_ms;
	uint32_t rto_ms;
	uint32_t srtt_ms;
	uint32_t rttvar_ms;
	uint32_t retry_count;
	uint32_t overflow_count;
	uint32_t replay_count;
	uint32_t lost_count;
	uint8_t lost_reason;
} peer_state_t;

struct keemash_rel_ctx {
	keemash_rel_config_t cfg;
	uint32_t local_session;
	uint32_t next_stream_id;
	peer_state_t *peers;
	tx_slot_t *tx;
	rx_slot_t *rx;
	reassembly_slot_t *reassembly;
	uint32_t data_counter;
	uint32_t ack_counter;
	uint32_t nack_counter;
	uint32_t duplicate_counter;
	uint32_t delay_counter;
	uint32_t reorder_counter;
	uint32_t overflow_counter;
	bool held_valid;
	uint8_t held_dst[6];
	size_t held_len;
	uint8_t held_packet[KM_PACKET_MAX];
	bool delayed_valid;
	uint8_t delayed_dst[6];
	uint32_t delayed_due_ms;
	size_t delayed_len;
	uint8_t delayed_packet[KM_PACKET_MAX];
};

static uint32_t now_ms(void)
{
	return (uint32_t)(esp_timer_get_time() / 1000ULL);
}

static bool seq_before(uint32_t a, uint32_t b)
{
	return (int32_t)(a - b) < 0;
}

static bool seq_after(uint32_t a, uint32_t b)
{
	return seq_before(b, a);
}

static bool seq_in_range(uint32_t seq, uint32_t first, uint32_t last)
{
	return (uint32_t)(seq - first) <= (uint32_t)(last - first);
}

static bool mac_eq(const uint8_t a[6], const uint8_t b[6])
{
	return memcmp(a, b, 6) == 0;
}

static bool mac_zero(const uint8_t mac[6])
{
	static const uint8_t zero[6] = {0};
	return mac_eq(mac, zero);
}

static void mac_copy(uint8_t dst[6], const uint8_t src[6])
{
	memcpy(dst, src, 6);
}

static void flush_delayed_packet(keemash_rel_ctx_t *ctx, uint32_t now)
{
	if (!ctx->delayed_valid ||
	    (int32_t)(now - ctx->delayed_due_ms) < 0) {
		return;
	}

	(void)ctx->cfg.send(ctx->cfg.user, ctx->delayed_dst,
			    ctx->delayed_packet, ctx->delayed_len);
	ctx->delayed_valid = false;
	ctx->delayed_len = 0;
}

static uint16_t crc16_update(uint16_t crc, const uint8_t *data, size_t len)
{
	while (len--) {
		crc ^= (uint16_t)(*data++) << 8;
		for (int i = 0; i < 8; i++) {
			crc = (crc & 0x8000U) ? (uint16_t)((crc << 1) ^ 0x1021U)
			                      : (uint16_t)(crc << 1);
		}
	}
	return crc;
}

static uint16_t packet_crc(const mesh_v2_hdr_t *h, const uint8_t *payload)
{
	mesh_v2_hdr_t copy = *h;
	copy.crc16 = 0;
	uint16_t crc = crc16_update(0xFFFFU, (const uint8_t *)&copy, sizeof(copy));
	return crc16_update(crc, payload, h->payload_len);
}

static bool packet_valid(const void *packet, size_t packet_len,
			 const mesh_v2_hdr_t **out_h, const uint8_t **out_payload)
{
	if (!packet || packet_len < sizeof(mesh_v2_hdr_t)) {
		return false;
	}
	const mesh_v2_hdr_t *h = (const mesh_v2_hdr_t *)packet;
	if (h->magic != MESH_PKT_MAGIC || h->version != MESH_PKT_VERSION_V2 ||
	    h->payload_len > MESH_V2_PAYLOAD_MAX ||
	    packet_len != sizeof(*h) + h->payload_len) {
		return false;
	}
	const uint8_t *payload = (const uint8_t *)packet + sizeof(*h);
	if (packet_crc(h, payload) != h->crc16) {
		return false;
	}
	if (out_h) *out_h = h;
	if (out_payload) *out_payload = payload;
	return true;
}

static peer_state_t *peer_find(keemash_rel_ctx_t *ctx, const uint8_t mac[6], bool create)
{
	const uint8_t zero[6] = {0};
	const uint8_t *key = ctx->cfg.root_role ? mac : zero;
	for (uint16_t i = 0; i < ctx->cfg.max_peers; i++) {
		if (ctx->peers[i].used && mac_eq(ctx->peers[i].mac, key)) {
			if (!ctx->cfg.root_role && mac && !mac_zero(mac)) {
				mac_copy(ctx->peers[i].remote_mac, mac);
			}
			return &ctx->peers[i];
		}
	}
	if (!create) {
		return NULL;
	}
	for (uint16_t i = 0; i < ctx->cfg.max_peers; i++) {
		peer_state_t *p = &ctx->peers[i];
		if (!p->used) {
			memset(p, 0, sizeof(*p));
			p->used = true;
			mac_copy(p->mac, key);
			if (mac && !mac_zero(mac)) mac_copy(p->remote_mac, mac);
			p->rto_ms = ctx->cfg.initial_rto_ms;
			for (uint8_t ch = 1; ch < KM_CHANNEL_COUNT; ch++) {
				p->next_seq[ch] = 1;
				p->expected_seq[ch] = 1;
			}
			return p;
		}
	}
	return NULL;
}

static const uint8_t *peer_send_mac(const keemash_rel_ctx_t *ctx, const peer_state_t *peer)
{
	return ctx->cfg.root_role ? peer->mac : peer->remote_mac;
}

static void notify_event(keemash_rel_ctx_t *ctx, const peer_state_t *peer,
			 uint8_t channel, uint8_t reason,
			 uint32_t first, uint32_t last)
{
	if (ctx->cfg.event) {
		ctx->cfg.event(ctx->cfg.user, peer_send_mac(ctx, peer),
			       channel, reason, first, last);
	}
}

static esp_err_t raw_send(keemash_rel_ctx_t *ctx, const uint8_t dst[6],
			  const void *packet, size_t len, uint8_t type)
{
	if (!ctx->cfg.send) {
		return ESP_ERR_INVALID_STATE;
	}
	uint32_t now = now_ms();
	flush_delayed_packet(ctx, now);

	uint32_t *counter = NULL;
	uint16_t every = 0;
	if (type == MESH_V2_TYPE_RELIABLE_DATA) {
		counter = &ctx->data_counter;
		every = ctx->cfg.fault_drop_data_every;
	} else if (type == MESH_V2_TYPE_RELIABLE_ACK) {
		counter = &ctx->ack_counter;
		every = ctx->cfg.fault_drop_ack_every;
	} else if (type == MESH_V2_TYPE_RELIABLE_NACK) {
		counter = &ctx->nack_counter;
		every = ctx->cfg.fault_drop_nack_every;
	}
	if (counter) {
		(*counter)++;
		if (every && (*counter % every) == 0) {
			return ESP_OK;
		}
	}

	if (type == MESH_V2_TYPE_RELIABLE_DATA && ctx->cfg.fault_delay_every &&
	    (++ctx->delay_counter % ctx->cfg.fault_delay_every) == 0 &&
	    !ctx->delayed_valid && len <= sizeof(ctx->delayed_packet)) {
		ctx->delayed_valid = true;
		mac_copy(ctx->delayed_dst, dst);
		ctx->delayed_due_ms = now +
			(ctx->cfg.fault_delay_ms ? ctx->cfg.fault_delay_ms : 250U);
		ctx->delayed_len = len;
		memcpy(ctx->delayed_packet, packet, len);
		return ESP_OK;
	}

	if (type == MESH_V2_TYPE_RELIABLE_DATA && ctx->cfg.fault_reorder_every &&
	    (++ctx->reorder_counter % ctx->cfg.fault_reorder_every) == 0 &&
	    !ctx->held_valid && len <= sizeof(ctx->held_packet)) {
		ctx->held_valid = true;
		mac_copy(ctx->held_dst, dst);
		ctx->held_len = len;
		memcpy(ctx->held_packet, packet, len);
		return ESP_OK;
	}

	esp_err_t err = ctx->cfg.send(ctx->cfg.user, dst, packet, len);
	if (ctx->held_valid) {
		(void)ctx->cfg.send(ctx->cfg.user, ctx->held_dst,
				    ctx->held_packet, ctx->held_len);
		ctx->held_valid = false;
	}
	if (type == MESH_V2_TYPE_RELIABLE_DATA && ctx->cfg.fault_duplicate_every &&
	    (++ctx->duplicate_counter % ctx->cfg.fault_duplicate_every) == 0) {
		(void)ctx->cfg.send(ctx->cfg.user, dst, packet, len);
	}
	return err;
}

static esp_err_t send_packet(keemash_rel_ctx_t *ctx, const uint8_t dst[6],
			     uint8_t type, uint32_t session_id,
			     const void *payload, size_t payload_len)
{
	if (payload_len > MESH_V2_PAYLOAD_MAX) {
		return ESP_ERR_INVALID_SIZE;
	}
	uint8_t packet[KM_PACKET_MAX] = {0};
	mesh_v2_hdr_t *h = (mesh_v2_hdr_t *)packet;
	h->magic = MESH_PKT_MAGIC;
	h->version = MESH_PKT_VERSION_V2;
	h->type = type;
	h->session_id = session_id;
	h->payload_len = (uint16_t)payload_len;
	mac_copy(h->src_mac, ctx->cfg.local_mac);
	if (payload_len) {
		memcpy(packet + sizeof(*h), payload, payload_len);
	}
	h->crc16 = packet_crc(h, packet + sizeof(*h));
	return raw_send(ctx, dst, packet, sizeof(*h) + payload_len, type);
}

static void record_lost(keemash_rel_ctx_t *ctx, peer_state_t *peer,
			uint8_t channel, uint8_t reason,
			uint32_t first, uint32_t last, uint32_t count);

static void clear_peer_buffers(keemash_rel_ctx_t *ctx, peer_state_t *peer,
			       uint8_t reason)
{
	const uint8_t *send_mac = peer_send_mac(ctx, peer);
	if (ctx->held_valid && mac_eq(ctx->held_dst, send_mac)) {
		ctx->held_valid = false;
		ctx->held_len = 0;
	}
	if (ctx->delayed_valid && mac_eq(ctx->delayed_dst, send_mac)) {
		ctx->delayed_valid = false;
		ctx->delayed_len = 0;
	}

	uint32_t first[KM_CHANNEL_COUNT] = {0};
	uint32_t last[KM_CHANNEL_COUNT] = {0};
	uint32_t count[KM_CHANNEL_COUNT] = {0};
	for (uint16_t i = 0; i < ctx->cfg.tx_slots; i++) {
		tx_slot_t *slot = &ctx->tx[i];
		if (slot->used && mac_eq(slot->peer, peer->mac)) {
			uint8_t ch = slot->channel;
			if (ch < KM_CHANNEL_COUNT) {
				if (count[ch] == 0 || seq_before(slot->seq, first[ch])) {
					first[ch] = slot->seq;
				}
				if (count[ch] == 0 || seq_after(slot->seq, last[ch])) {
					last[ch] = slot->seq;
				}
				count[ch]++;
			}
			memset(slot, 0, sizeof(*slot));
		}
	}
	for (uint16_t i = 0; i < ctx->cfg.rx_slots; i++) {
		if (ctx->rx[i].used && mac_eq(ctx->rx[i].peer, peer->mac)) {
			record_lost(ctx, peer, ctx->rx[i].channel, reason,
				    ctx->rx[i].seq, ctx->rx[i].seq, 1);
			memset(&ctx->rx[i], 0, sizeof(ctx->rx[i]));
		}
	}
	for (uint16_t i = 0; i < ctx->cfg.reassembly_slots; i++) {
		if (ctx->reassembly[i].used &&
		    mac_eq(ctx->reassembly[i].peer, peer->mac)) {
			uint32_t first_seq = ctx->reassembly[i].first_seq;
			uint32_t last_seq = first_seq +
				ctx->reassembly[i].fragment_count - 1U;
			record_lost(ctx, peer, ctx->reassembly[i].channel, reason,
				    first_seq, last_seq,
				    ctx->reassembly[i].fragment_count);
			memset(&ctx->reassembly[i], 0, sizeof(ctx->reassembly[i]));
		}
	}
	for (uint8_t ch = 1; ch < KM_CHANNEL_COUNT; ch++) {
		peer->next_seq[ch] = 1;
		peer->expected_seq[ch] = 1;
	}
	memset(peer->pending_lost, 0, sizeof(peer->pending_lost));
	peer->ready = false;
	for (uint8_t ch = 1; ch < KM_CHANNEL_COUNT; ch++) {
		if (count[ch]) {
			record_lost(ctx, peer, ch, reason, first[ch], last[ch],
				    count[ch]);
		}
	}
}

static uint32_t tx_unacked(const keemash_rel_ctx_t *ctx, const peer_state_t *peer)
{
	uint32_t count = 0;
	for (uint16_t i = 0; i < ctx->cfg.tx_slots; i++) {
		if (ctx->tx[i].used && mac_eq(ctx->tx[i].peer, peer->mac)) count++;
	}
	return count;
}

static uint32_t rx_depth(const keemash_rel_ctx_t *ctx, const peer_state_t *peer)
{
	uint32_t count = 0;
	for (uint16_t i = 0; i < ctx->cfg.rx_slots; i++) {
		if (ctx->rx[i].used && mac_eq(ctx->rx[i].peer, peer->mac)) count++;
	}
	return count;
}

static tx_slot_t *tx_alloc(keemash_rel_ctx_t *ctx, uint8_t priority)
{
	uint32_t free_count = 0;
	for (uint16_t i = 0; i < ctx->cfg.tx_slots; i++) {
		if (!ctx->tx[i].used) free_count++;
	}
	if (priority < KEEMASH_REL_PRIORITY_CONTROL &&
	    free_count <= ctx->cfg.reserved_control_slots) {
		return NULL;
	}
	for (uint16_t i = 0; i < ctx->cfg.tx_slots; i++) {
		if (!ctx->tx[i].used) return &ctx->tx[i];
	}
	return NULL;
}

static uint32_t tx_available(const keemash_rel_ctx_t *ctx, uint8_t priority)
{
	uint32_t free_count = 0;
	for (uint16_t i = 0; i < ctx->cfg.tx_slots; i++) {
		if (!ctx->tx[i].used) free_count++;
	}
	if (priority < KEEMASH_REL_PRIORITY_CONTROL) {
		if (free_count <= ctx->cfg.reserved_control_slots) return 0;
		free_count -= ctx->cfg.reserved_control_slots;
	}
	return free_count;
}

static tx_slot_t *tx_find(keemash_rel_ctx_t *ctx, const peer_state_t *peer,
			  uint8_t channel, uint32_t seq)
{
	for (uint16_t i = 0; i < ctx->cfg.tx_slots; i++) {
		tx_slot_t *slot = &ctx->tx[i];
		if (slot->used && slot->channel == channel && slot->seq == seq &&
		    mac_eq(slot->peer, peer->mac)) {
			return slot;
		}
	}
	return NULL;
}

static rx_slot_t *rx_find(keemash_rel_ctx_t *ctx, const peer_state_t *peer,
			  uint8_t channel, uint32_t seq)
{
	for (uint16_t i = 0; i < ctx->cfg.rx_slots; i++) {
		rx_slot_t *slot = &ctx->rx[i];
		if (slot->used && slot->channel == channel && slot->seq == seq &&
		    mac_eq(slot->peer, peer->mac)) {
			return slot;
		}
	}
	return NULL;
}

static rx_slot_t *rx_alloc(keemash_rel_ctx_t *ctx)
{
	for (uint16_t i = 0; i < ctx->cfg.rx_slots; i++) {
		if (!ctx->rx[i].used) return &ctx->rx[i];
	}
	return NULL;
}

static uint32_t sack_bitmap(keemash_rel_ctx_t *ctx, const peer_state_t *peer,
			    uint8_t channel)
{
	uint32_t ack = peer->expected_seq[channel] - 1;
	uint32_t bitmap = 0;
	for (uint8_t bit = 0; bit < MESH_V2_RELIABLE_WINDOW; bit++) {
		if (rx_find(ctx, peer, channel, ack + 1U + bit)) {
			bitmap |= 1UL << bit;
		}
	}
	return bitmap;
}

static reassembly_slot_t *reassembly_find(keemash_rel_ctx_t *ctx,
					  const peer_state_t *peer,
					  const mesh_v2_reliable_hdr_t *rh,
					  bool create)
{
	for (uint16_t i = 0; i < ctx->cfg.reassembly_slots; i++) {
		reassembly_slot_t *slot = &ctx->reassembly[i];
		if (slot->used && slot->channel == rh->channel_id &&
		    slot->stream_id == rh->stream_id &&
		    mac_eq(slot->peer, peer->mac)) {
			if (slot->fragment_count != rh->fragment_count ||
			    slot->first_seq != rh->seq - rh->fragment_index) {
				return NULL;
			}
			return slot;
		}
	}
	if (!create) return NULL;
	for (uint16_t i = 0; i < ctx->cfg.reassembly_slots; i++) {
		reassembly_slot_t *slot = &ctx->reassembly[i];
		if (!slot->used) {
			memset(slot, 0, sizeof(*slot));
			slot->used = true;
			mac_copy(slot->peer, peer->mac);
			slot->channel = rh->channel_id;
			slot->stream_id = rh->stream_id;
			slot->fragment_count = rh->fragment_count;
			slot->first_seq = rh->seq - rh->fragment_index;
			slot->last_ms = now_ms();
			return slot;
		}
	}
	return NULL;
}

static esp_err_t send_lost_packet(keemash_rel_ctx_t *ctx, peer_state_t *peer,
				  uint8_t channel, uint8_t reason,
				  uint16_t flags, uint32_t first,
				  uint32_t last);
static void consume_contiguous(keemash_rel_ctx_t *ctx, peer_state_t *peer,
			       uint8_t channel);
static void receiver_drop_range(keemash_rel_ctx_t *ctx, peer_state_t *peer,
				uint8_t channel, uint8_t reason,
				uint32_t first, uint32_t last);

static void record_lost(keemash_rel_ctx_t *ctx, peer_state_t *peer,
			uint8_t channel, uint8_t reason,
			uint32_t first, uint32_t last, uint32_t count)
{
	peer->lost_reason = reason;
	peer->lost_count += count ? count : 1U;
	notify_event(ctx, peer, channel, reason, first, last);
}

static void deliver_fragment(keemash_rel_ctx_t *ctx, peer_state_t *peer,
			     const mesh_v2_reliable_hdr_t *rh,
			     const uint8_t *payload)
{
	if (rh->fragment_count <= 1) {
		if (ctx->cfg.deliver) {
			ctx->cfg.deliver(ctx->cfg.user, peer_send_mac(ctx, peer),
					 rh->channel_id, payload, rh->payload_len,
					 rh->stream_id);
		}
		return;
	}
	if (rh->fragment_count > MESH_V2_RELIABLE_MAX_FRAGMENTS ||
	    rh->fragment_index >= rh->fragment_count) {
		return;
	}
	reassembly_slot_t *slot = reassembly_find(ctx, peer, rh, true);
	if (!slot) {
		peer->overflow_count++;
		uint32_t first = rh->seq - rh->fragment_index;
		uint32_t last = first + rh->fragment_count - 1U;
		receiver_drop_range(ctx, peer, rh->channel_id,
				    MESH_V2_LOST_REASON_OVERFLOW, first, last);
		return;
	}
	size_t offset = (size_t)rh->fragment_index * MESH_V2_RELIABLE_INNER_MAX;
	memcpy(slot->data + offset, payload, rh->payload_len);
	slot->fragment_len[rh->fragment_index] = rh->payload_len;
	slot->received_mask |= (uint16_t)(1U << rh->fragment_index);
	slot->last_ms = now_ms();
	uint16_t complete = (uint16_t)((1UL << rh->fragment_count) - 1UL);
	if (slot->received_mask != complete) return;

	size_t total = 0;
	for (uint8_t i = 0; i < slot->fragment_count; i++) total += slot->fragment_len[i];
	if (ctx->cfg.deliver) {
		ctx->cfg.deliver(ctx->cfg.user, peer_send_mac(ctx, peer),
				 slot->channel, slot->data, total, slot->stream_id);
	}
	memset(slot, 0, sizeof(*slot));
}

static bool pending_lost_add(peer_state_t *peer, uint8_t channel,
			     uint32_t first, uint32_t last)
{
	for (uint8_t pass = 0; pass < KM_PENDING_LOST_RANGES; pass++) {
		bool merged = false;
		for (uint8_t i = 0; i < KM_PENDING_LOST_RANGES; i++) {
			pending_lost_range_t *range = &peer->pending_lost[i];
			if (!range->used || range->channel != channel) continue;
			bool overlap = seq_in_range(first, range->first, range->last) ||
				       seq_in_range(last, range->first, range->last) ||
				       seq_in_range(range->first, first, last) ||
				       seq_in_range(range->last, first, last) ||
				       range->last + 1U == first || last + 1U == range->first;
			if (!overlap) continue;
			if (seq_before(first, range->first)) range->first = first;
			if (seq_after(last, range->last)) range->last = last;
			first = range->first;
			last = range->last;
			merged = true;
			for (uint8_t j = 0; j < KM_PENDING_LOST_RANGES; j++) {
				pending_lost_range_t *other = &peer->pending_lost[j];
				if (other == range || !other->used ||
				    other->channel != channel) {
					continue;
				}
				bool join = seq_in_range(other->first, range->first, range->last) ||
					    seq_in_range(other->last, range->first, range->last) ||
					    seq_in_range(range->first, other->first, other->last) ||
					    seq_in_range(range->last, other->first, other->last) ||
					    range->last + 1U == other->first ||
					    other->last + 1U == range->first;
				if (!join) continue;
				if (seq_before(other->first, range->first)) {
					range->first = other->first;
				}
				if (seq_after(other->last, range->last)) {
					range->last = other->last;
				}
				memset(other, 0, sizeof(*other));
				first = range->first;
				last = range->last;
			}
			break;
		}
		if (!merged) break;
	}

	for (uint8_t i = 0; i < KM_PENDING_LOST_RANGES; i++) {
		pending_lost_range_t *range = &peer->pending_lost[i];
		if (range->used && range->channel == channel &&
		    seq_in_range(first, range->first, range->last) &&
		    seq_in_range(last, range->first, range->last)) {
			return true;
		}
	}
	for (uint8_t i = 0; i < KM_PENDING_LOST_RANGES; i++) {
		pending_lost_range_t *range = &peer->pending_lost[i];
		if (!range->used) {
			range->used = true;
			range->channel = channel;
			range->first = first;
			range->last = last;
			return true;
		}
	}
	return false;
}

static void consume_contiguous(keemash_rel_ctx_t *ctx, peer_state_t *peer,
			       uint8_t channel)
{
	for (;;) {
		bool skipped_lost = false;
		for (uint8_t i = 0; i < KM_PENDING_LOST_RANGES; i++) {
			pending_lost_range_t *range = &peer->pending_lost[i];
			if (!range->used || range->channel != channel ||
			    !seq_in_range(peer->expected_seq[channel],
					  range->first, range->last)) {
				continue;
			}
			peer->expected_seq[channel] = range->last + 1U;
			memset(range, 0, sizeof(*range));
			skipped_lost = true;
			break;
		}
		if (skipped_lost) {
			continue;
		}
		rx_slot_t *slot = rx_find(ctx, peer, channel, peer->expected_seq[channel]);
		if (!slot) break;
		mesh_v2_reliable_hdr_t rh = slot->hdr;
		uint8_t payload[MESH_V2_RELIABLE_INNER_MAX];
		memcpy(payload, slot->payload, slot->payload_len);
		memset(slot, 0, sizeof(*slot));
		peer->expected_seq[channel]++;
		deliver_fragment(ctx, peer, &rh, payload);
	}
}

static void receiver_drop_range(keemash_rel_ctx_t *ctx, peer_state_t *peer,
				uint8_t channel, uint8_t reason,
				uint32_t first, uint32_t last)
{
	for (uint16_t i = 0; i < ctx->cfg.rx_slots; i++) {
		rx_slot_t *slot = &ctx->rx[i];
		if (slot->used && slot->channel == channel &&
		    mac_eq(slot->peer, peer->mac) &&
		    seq_in_range(slot->seq, first, last)) {
			memset(slot, 0, sizeof(*slot));
		}
	}
	for (uint16_t i = 0; i < ctx->cfg.reassembly_slots; i++) {
		reassembly_slot_t *slot = &ctx->reassembly[i];
		if (!slot->used || slot->channel != channel ||
		    !mac_eq(slot->peer, peer->mac)) {
			continue;
		}
		uint32_t slot_last = slot->first_seq + slot->fragment_count - 1U;
		bool overlap = seq_in_range(slot->first_seq, first, last) ||
			       seq_in_range(slot_last, first, last) ||
			       seq_in_range(first, slot->first_seq, slot_last);
		if (overlap) memset(slot, 0, sizeof(*slot));
	}

	uint32_t count = (uint32_t)(last - first) + 1U;
	record_lost(ctx, peer, channel, reason, first, last, count);
	uint32_t *expected = &peer->expected_seq[channel];
	if (seq_in_range(*expected, first, last)) {
		*expected = last + 1U;
		consume_contiguous(ctx, peer, channel);
	} else if (seq_before(*expected, first) &&
		   !pending_lost_add(peer, channel, first, last)) {
		clear_peer_buffers(ctx, peer, MESH_V2_LOST_REASON_OVERFLOW);
		return;
	}
	(void)send_lost_packet(ctx, peer, channel, reason,
			      MESH_V2_LOST_FLAG_RECEIVER_DROP, first, last);
}

static esp_err_t send_ack(keemash_rel_ctx_t *ctx, peer_state_t *peer,
			  const mesh_v2_reliable_hdr_t *rh, bool nack)
{
	mesh_v2_reliable_ack_payload_t ack = {0};
	ack.channel_id = rh->channel_id;
	ack.root_session_id = peer->root_session_id;
	ack.node_session_id = peer->node_session_id;
	ack.ack_seq = peer->expected_seq[rh->channel_id] - 1;
	ack.sack_bitmap = sack_bitmap(ctx, peer, rh->channel_id);
	ack.nack_seq = nack ? peer->expected_seq[rh->channel_id] : 0;
	ack.echo_tx_ms = rh->tx_ms;
	mac_copy(ack.origin_mac, rh->origin_mac);
	mac_copy(ack.target_mac, rh->target_mac);
	return send_packet(ctx, peer_send_mac(ctx, peer),
			   nack ? MESH_V2_TYPE_RELIABLE_NACK : MESH_V2_TYPE_RELIABLE_ACK,
			   ctx->local_session, &ack, sizeof(ack));
}

static esp_err_t send_lost_packet(keemash_rel_ctx_t *ctx, peer_state_t *peer,
				  uint8_t channel, uint8_t reason,
				  uint16_t flags, uint32_t first,
				  uint32_t last)
{
	mesh_v2_reliable_lost_payload_t lost = {0};
	lost.channel_id = channel;
	lost.reason = reason;
	lost.rsv = flags;
	lost.root_session_id = peer->root_session_id;
	lost.node_session_id = peer->node_session_id;
	lost.seq_first = first;
	lost.seq_last = last;
	mac_copy(lost.origin_mac, ctx->cfg.local_mac);
	mac_copy(lost.target_mac, peer_send_mac(ctx, peer));
	return send_packet(ctx, peer_send_mac(ctx, peer),
			   MESH_V2_TYPE_RELIABLE_LOST, ctx->local_session,
			   &lost, sizeof(lost));
}

static esp_err_t send_lost(keemash_rel_ctx_t *ctx, peer_state_t *peer,
			   uint8_t channel, uint8_t reason,
			   uint32_t first, uint32_t last)
{
	uint32_t count = (uint32_t)(last - first) + 1U;
	record_lost(ctx, peer, channel, reason, first, last, count);
	return send_lost_packet(ctx, peer, channel, reason, 0, first, last);
}

static void update_rto(keemash_rel_ctx_t *ctx, peer_state_t *peer, uint32_t sample)
{
	if (sample == 0 || sample > 60000U) return;
	if (peer->srtt_ms == 0) {
		peer->srtt_ms = sample;
		peer->rttvar_ms = sample / 2U;
	} else {
		uint32_t diff = peer->srtt_ms > sample ? peer->srtt_ms - sample
						      : sample - peer->srtt_ms;
		peer->rttvar_ms = (3U * peer->rttvar_ms + diff) / 4U;
		peer->srtt_ms = (7U * peer->srtt_ms + sample) / 8U;
	}
	uint32_t rto = peer->srtt_ms + 4U * peer->rttvar_ms;
	if (rto < ctx->cfg.min_rto_ms) rto = ctx->cfg.min_rto_ms;
	if (rto > ctx->cfg.max_rto_ms) rto = ctx->cfg.max_rto_ms;
	peer->rto_ms = rto;
}

static void ack_slots(keemash_rel_ctx_t *ctx, peer_state_t *peer,
		      const mesh_v2_reliable_ack_payload_t *ack)
{
	uint32_t now = now_ms();
	for (uint16_t i = 0; i < ctx->cfg.tx_slots; i++) {
		tx_slot_t *slot = &ctx->tx[i];
		if (!slot->used || slot->channel != ack->channel_id ||
		    !mac_eq(slot->peer, peer->mac)) continue;
		bool accepted = !seq_after(slot->seq, ack->ack_seq);
		if (!accepted) {
			uint32_t delta = slot->seq - ack->ack_seq - 1U;
			accepted = delta < 32U && (ack->sack_bitmap & (1UL << delta));
		}
		if (accepted) {
			if (slot->retries == 0 && slot->first_sent_ms) {
				update_rto(ctx, peer, now - slot->first_sent_ms);
			}
			memset(slot, 0, sizeof(*slot));
		}
	}
	peer->last_ack_ms = now;
}

static esp_err_t retransmit_slot(keemash_rel_ctx_t *ctx, peer_state_t *peer,
				 tx_slot_t *slot)
{
	mesh_v2_hdr_t *h = (mesh_v2_hdr_t *)slot->bytes;
	mesh_v2_reliable_hdr_t *rh =
		(mesh_v2_reliable_hdr_t *)(slot->bytes + sizeof(*h));
	rh->flags |= MESH_V2_RELIABLE_FLAG_REPLAY;
	rh->tx_ms = now_ms();
	h->crc16 = packet_crc(h, slot->bytes + sizeof(*h));
	slot->last_sent_ms = rh->tx_ms;
	slot->retries++;
	peer->retry_count++;
	peer->replay_count++;
	return raw_send(ctx, peer_send_mac(ctx, peer), slot->bytes, slot->len,
			MESH_V2_TYPE_RELIABLE_DATA);
}

esp_err_t keemash_rel_init(keemash_rel_ctx_t **out, const keemash_rel_config_t *config)
{
	if (!out || !config || !config->send || config->max_peers == 0 ||
	    config->tx_slots == 0 || config->rx_slots == 0 ||
	    config->reassembly_slots == 0) {
		return ESP_ERR_INVALID_ARG;
	}
	keemash_rel_ctx_t *ctx = calloc(1, sizeof(*ctx));
	if (!ctx) return ESP_ERR_NO_MEM;
	ctx->cfg = *config;
	ctx->local_session = esp_random();
	if (!ctx->local_session) ctx->local_session = 1;
	ctx->next_stream_id = esp_random();
	if (!ctx->next_stream_id) ctx->next_stream_id = 1;
	ctx->peers = calloc(config->max_peers, sizeof(*ctx->peers));
	ctx->tx = calloc(config->tx_slots, sizeof(*ctx->tx));
	ctx->rx = calloc(config->rx_slots, sizeof(*ctx->rx));
	ctx->reassembly = calloc(config->reassembly_slots, sizeof(*ctx->reassembly));
	if (!ctx->peers || !ctx->tx || !ctx->rx || !ctx->reassembly) {
		keemash_rel_deinit(ctx);
		return ESP_ERR_NO_MEM;
	}
	*out = ctx;
	return ESP_OK;
}

void keemash_rel_deinit(keemash_rel_ctx_t *ctx)
{
	if (!ctx) return;
	free(ctx->peers);
	free(ctx->tx);
	free(ctx->rx);
	free(ctx->reassembly);
	free(ctx);
}

uint32_t keemash_rel_local_session(const keemash_rel_ctx_t *ctx)
{
	return ctx ? ctx->local_session : 0;
}

esp_err_t keemash_rel_send_hello(keemash_rel_ctx_t *ctx, const uint8_t peer_mac[6],
				 const char *tag, uint32_t uptime_s,
				 uint32_t capabilities)
{
	if (!ctx || ctx->cfg.root_role) return ESP_ERR_INVALID_STATE;
	peer_state_t *peer = peer_find(ctx, peer_mac, true);
	if (!peer) return ESP_ERR_NO_MEM;
	mesh_v2_reliable_hello_payload_t hello = {0};
	if (tag) strncpy(hello.tag, tag, sizeof(hello.tag) - 1);
	hello.uptime_s = uptime_s;
	hello.profile_version = MESH_V2_RELIABLE_PROFILE_VERSION;
	hello.mtu = MESH_V2_PACKET_MAX;
	hello.tx_slots = ctx->cfg.tx_slots;
	hello.reorder_window = MESH_V2_RELIABLE_WINDOW;
	hello.capabilities = capabilities | MESH_V2_CAP_RELIABLE_E2E |
				     MESH_V2_CAP_SACK | MESH_V2_CAP_FRAGMENT;
	hello.node_session_id = ctx->local_session;
	hello.root_session_seen = peer->root_session_id;
	return send_packet(ctx, peer_send_mac(ctx, peer),
			   MESH_V2_TYPE_RELIABLE_HELLO, ctx->local_session,
			   &hello, sizeof(hello));
}

esp_err_t keemash_rel_send(keemash_rel_ctx_t *ctx, const uint8_t peer_mac[6],
			   uint8_t channel, const void *payload, size_t payload_len,
			   uint8_t priority)
{
	if (!ctx || !payload || payload_len == 0 || channel == 0 ||
	    channel >= KM_CHANNEL_COUNT || payload_len > KM_MESSAGE_MAX) {
		return ESP_ERR_INVALID_ARG;
	}
	peer_state_t *peer = peer_find(ctx, peer_mac, false);
	if (!peer || !peer->ready) return ESP_ERR_INVALID_STATE;
	uint8_t fragments = (uint8_t)((payload_len + MESH_V2_RELIABLE_INNER_MAX - 1U) /
				      MESH_V2_RELIABLE_INNER_MAX);
	if (fragments == 0 || fragments > MESH_V2_RELIABLE_MAX_FRAGMENTS) {
		return ESP_ERR_INVALID_SIZE;
	}
	uint32_t first_seq = peer->next_seq[channel];
	uint32_t stream_id = ctx->next_stream_id++;
	if (!stream_id) stream_id = ctx->next_stream_id++;
	bool forced_overflow = ctx->cfg.fault_overflow_every &&
		(++ctx->overflow_counter % ctx->cfg.fault_overflow_every) == 0;
	if (forced_overflow || tx_available(ctx, priority) < fragments) {
		uint32_t last_seq = first_seq + fragments - 1U;
		peer->next_seq[channel] += fragments;
		peer->overflow_count++;
		(void)send_lost(ctx, peer, channel, MESH_V2_LOST_REASON_OVERFLOW,
				first_seq, last_seq);
		return ESP_ERR_NO_MEM;
	}

	tx_slot_t *slots[MESH_V2_RELIABLE_MAX_FRAGMENTS] = {0};
	for (uint8_t i = 0; i < fragments; i++) {
		tx_slot_t *slot = tx_alloc(ctx, priority);
		uint32_t seq = peer->next_seq[channel]++;
		if (!slot) {
			for (uint8_t j = 0; j < i; j++) memset(slots[j], 0, sizeof(*slots[j]));
			uint32_t last_seq = first_seq + fragments - 1U;
			peer->next_seq[channel] = last_seq + 1U;
			peer->overflow_count++;
			(void)send_lost(ctx, peer, channel, MESH_V2_LOST_REASON_OVERFLOW,
					first_seq, last_seq);
			return ESP_ERR_NO_MEM;
		}
		slots[i] = slot;
		memset(slot, 0, sizeof(*slot));
		slot->used = true;
		slot->channel = channel;
		slot->priority = priority;
		slot->seq = seq;
		slot->stream_id = stream_id;
		mac_copy(slot->peer, peer->mac);

		mesh_v2_hdr_t *h = (mesh_v2_hdr_t *)slot->bytes;
		mesh_v2_reliable_hdr_t *rh =
			(mesh_v2_reliable_hdr_t *)(slot->bytes + sizeof(*h));
		size_t offset = (size_t)i * MESH_V2_RELIABLE_INNER_MAX;
		size_t chunk = payload_len - offset;
		if (chunk > MESH_V2_RELIABLE_INNER_MAX) chunk = MESH_V2_RELIABLE_INNER_MAX;
		h->magic = MESH_PKT_MAGIC;
		h->version = MESH_PKT_VERSION_V2;
		h->type = MESH_V2_TYPE_RELIABLE_DATA;
		h->session_id = ctx->local_session;
		h->payload_len = (uint16_t)(sizeof(*rh) + chunk);
		mac_copy(h->src_mac, ctx->cfg.local_mac);
		rh->channel_id = channel;
		rh->flags = fragments > 1 ? MESH_V2_RELIABLE_FLAG_FRAGMENT : 0;
		if (priority == KEEMASH_REL_PRIORITY_CONTROL) rh->flags |= MESH_V2_RELIABLE_FLAG_URGENT;
		rh->priority = priority;
		rh->fragment_count = fragments;
		rh->payload_len = (uint16_t)chunk;
		rh->fragment_index = i;
		rh->stream_id = stream_id;
		rh->seq = seq;
		rh->tx_ms = now_ms();
		rh->root_session_id = peer->root_session_id;
		rh->node_session_id = peer->node_session_id;
		mac_copy(rh->origin_mac, ctx->cfg.local_mac);
		mac_copy(rh->target_mac, peer_send_mac(ctx, peer));
		memcpy((uint8_t *)rh + sizeof(*rh), (const uint8_t *)payload + offset, chunk);
		h->crc16 = packet_crc(h, slot->bytes + sizeof(*h));
		slot->len = sizeof(*h) + h->payload_len;
		slot->first_sent_ms = rh->tx_ms;
		slot->last_sent_ms = rh->tx_ms;
	}

	esp_err_t first_err = ESP_OK;
	for (uint8_t i = 0; i < fragments; i++) {
		tx_slot_t *slot = slots[i];
		esp_err_t err = raw_send(ctx, peer_send_mac(ctx, peer),
					 slot->bytes, slot->len,
					 MESH_V2_TYPE_RELIABLE_DATA);
		if (err != ESP_OK && first_err == ESP_OK) first_err = err;
	}
	return first_err;
}

static esp_err_t handle_hello(keemash_rel_ctx_t *ctx, const uint8_t from[6],
			      const mesh_v2_reliable_hello_payload_t *hello)
{
	const uint32_t required = MESH_V2_CAP_RELIABLE_E2E |
				 MESH_V2_CAP_SACK | MESH_V2_CAP_FRAGMENT;
	if (!ctx->cfg.root_role || hello->profile_version != MESH_V2_RELIABLE_PROFILE_VERSION) {
		return ESP_ERR_NOT_SUPPORTED;
	}
	if ((hello->capabilities & required) != required ||
	    hello->mtu < sizeof(mesh_v2_hdr_t) + sizeof(mesh_v2_reliable_hdr_t) + 1U ||
	    hello->reorder_window < MESH_V2_RELIABLE_WINDOW) {
		return ESP_ERR_NOT_SUPPORTED;
	}
	peer_state_t *peer = peer_find(ctx, from, true);
	if (!peer) return ESP_ERR_NO_MEM;
	bool reset = peer->node_session_id != hello->node_session_id ||
		     hello->root_session_seen != ctx->local_session;
	if (reset) {
		clear_peer_buffers(ctx, peer, MESH_V2_LOST_REASON_SESSION_RESET);
	}
	peer->root_session_id = ctx->local_session;
	peer->node_session_id = hello->node_session_id;
	peer->ready = true;
	mesh_v2_reliable_hello_ack_payload_t ack = {
		.profile_version = MESH_V2_RELIABLE_PROFILE_VERSION,
		.mtu = MESH_V2_PACKET_MAX,
		.capabilities = MESH_V2_CAP_RELIABLE_E2E | MESH_V2_CAP_SACK |
				MESH_V2_CAP_FRAGMENT | MESH_V2_CAP_TYPED_CONTROL |
				MESH_V2_CAP_TYPED_MEMORY,
		.root_session_id = ctx->local_session,
		.node_session_id = hello->node_session_id,
		.reset_link = reset ? 1 : 0,
	};
	return send_packet(ctx, from, MESH_V2_TYPE_RELIABLE_HELLO_ACK,
			   ctx->local_session, &ack, sizeof(ack));
}

static esp_err_t handle_hello_ack(keemash_rel_ctx_t *ctx, const uint8_t from[6],
				  const mesh_v2_reliable_hello_ack_payload_t *ack)
{
	const uint32_t required = MESH_V2_CAP_RELIABLE_E2E |
				 MESH_V2_CAP_SACK | MESH_V2_CAP_FRAGMENT;
	if (ctx->cfg.root_role || ack->profile_version != MESH_V2_RELIABLE_PROFILE_VERSION ||
	    ack->node_session_id != ctx->local_session ||
	    (ack->capabilities & required) != required) {
		return ESP_ERR_INVALID_STATE;
	}
	peer_state_t *peer = peer_find(ctx, from, true);
	if (!peer) return ESP_ERR_NO_MEM;
	if (ack->reset_link ||
	    (peer->root_session_id && peer->root_session_id != ack->root_session_id)) {
		clear_peer_buffers(ctx, peer, MESH_V2_LOST_REASON_SESSION_RESET);
	}
	peer->root_session_id = ack->root_session_id;
	peer->node_session_id = ctx->local_session;
	peer->ready = true;
	peer->last_ack_ms = now_ms();
	return ESP_OK;
}

static esp_err_t handle_data(keemash_rel_ctx_t *ctx, const uint8_t from[6],
			     const mesh_v2_reliable_hdr_t *rh,
			     const uint8_t *payload, size_t payload_space)
{
	if (rh->channel_id == 0 || rh->channel_id >= KM_CHANNEL_COUNT ||
	    rh->payload_len > payload_space ||
	    rh->payload_len > MESH_V2_RELIABLE_INNER_MAX ||
	    rh->fragment_count == 0 ||
	    rh->fragment_count > MESH_V2_RELIABLE_MAX_FRAGMENTS ||
	    rh->fragment_index >= rh->fragment_count ||
	    (rh->fragment_count > 1 &&
	     !(rh->flags & MESH_V2_RELIABLE_FLAG_FRAGMENT)) ||
	    !mac_eq(rh->origin_mac, from) ||
	    !mac_eq(rh->target_mac, ctx->cfg.local_mac)) {
		return ESP_ERR_INVALID_ARG;
	}
	peer_state_t *peer = peer_find(ctx, from, false);
	if (!peer || !peer->ready ||
	    peer->root_session_id != rh->root_session_id ||
	    peer->node_session_id != rh->node_session_id) {
		return ESP_ERR_INVALID_STATE;
	}
	uint32_t expected = peer->expected_seq[rh->channel_id];
	peer->last_rx_ms = now_ms();
	if (rh->flags & MESH_V2_RELIABLE_FLAG_REPLAY) {
		peer->replay_count++;
	}
	if (seq_before(rh->seq, expected)) {
		return send_ack(ctx, peer, rh, false);
	}
	if (rh->seq == expected) {
		peer->expected_seq[rh->channel_id]++;
		deliver_fragment(ctx, peer, rh, payload);
		consume_contiguous(ctx, peer, rh->channel_id);
		return send_ack(ctx, peer, rh, false);
	}
	if ((uint32_t)(rh->seq - expected) >= MESH_V2_RELIABLE_WINDOW) {
		return send_ack(ctx, peer, rh, true);
	}
	if (!rx_find(ctx, peer, rh->channel_id, rh->seq)) {
		rx_slot_t *slot = rx_alloc(ctx);
		if (!slot) {
			peer->overflow_count++;
			receiver_drop_range(ctx, peer, rh->channel_id,
					    MESH_V2_LOST_REASON_OVERFLOW,
					    rh->seq, rh->seq);
			return ESP_ERR_NO_MEM;
		}
		memset(slot, 0, sizeof(*slot));
		slot->used = true;
		mac_copy(slot->peer, peer->mac);
		slot->channel = rh->channel_id;
		slot->seq = rh->seq;
		slot->hdr = *rh;
		slot->payload_len = rh->payload_len;
		memcpy(slot->payload, payload, rh->payload_len);
	}
	return send_ack(ctx, peer, rh, true);
}

static esp_err_t handle_ack_packet(keemash_rel_ctx_t *ctx, const uint8_t from[6],
				   const mesh_v2_reliable_ack_payload_t *ack,
				   bool nack)
{
	peer_state_t *peer = peer_find(ctx, from, false);
	if (!peer || !peer->ready ||
	    peer->root_session_id != ack->root_session_id ||
	    peer->node_session_id != ack->node_session_id ||
	    ack->channel_id == 0 || ack->channel_id >= KM_CHANNEL_COUNT ||
	    !mac_eq(ack->origin_mac, ctx->cfg.local_mac) ||
	    !mac_eq(ack->target_mac, from)) {
		return ESP_ERR_INVALID_STATE;
	}
	ack_slots(ctx, peer, ack);
	if (nack && ack->nack_seq) {
		tx_slot_t *slot = tx_find(ctx, peer, ack->channel_id, ack->nack_seq);
		if (slot) {
			return retransmit_slot(ctx, peer, slot);
		}
		return send_lost(ctx, peer, ack->channel_id,
				 MESH_V2_LOST_REASON_OVERFLOW,
				 ack->nack_seq, ack->nack_seq);
	}
	return ESP_OK;
}

static esp_err_t handle_lost_packet(keemash_rel_ctx_t *ctx, const uint8_t from[6],
				    const mesh_v2_reliable_lost_payload_t *lost)
{
	peer_state_t *peer = peer_find(ctx, from, false);
	if (!peer || !peer->ready ||
	    peer->root_session_id != lost->root_session_id ||
	    peer->node_session_id != lost->node_session_id ||
	    lost->channel_id == 0 || lost->channel_id >= KM_CHANNEL_COUNT ||
	    !mac_eq(lost->origin_mac, from) ||
	    !mac_eq(lost->target_mac, ctx->cfg.local_mac)) {
		return ESP_ERR_INVALID_STATE;
	}
	uint32_t lost_count = (uint32_t)(lost->seq_last - lost->seq_first) + 1U;
	if (lost->rsv & MESH_V2_LOST_FLAG_RECEIVER_DROP) {
		for (uint16_t i = 0; i < ctx->cfg.tx_slots; i++) {
			tx_slot_t *slot = &ctx->tx[i];
			if (slot->used && slot->channel == lost->channel_id &&
			    mac_eq(slot->peer, peer->mac) &&
			    seq_in_range(slot->seq, lost->seq_first, lost->seq_last)) {
				memset(slot, 0, sizeof(*slot));
			}
		}
		record_lost(ctx, peer, lost->channel_id, lost->reason,
			    lost->seq_first, lost->seq_last, lost_count);
		return ESP_OK;
	}
	uint32_t *expected = &peer->expected_seq[lost->channel_id];
	if (seq_in_range(*expected, lost->seq_first, lost->seq_last)) {
		*expected = lost->seq_last + 1U;
		consume_contiguous(ctx, peer, lost->channel_id);
	} else if (seq_before(*expected, lost->seq_first)) {
		if (!pending_lost_add(peer, lost->channel_id,
				      lost->seq_first, lost->seq_last)) {
			clear_peer_buffers(ctx, peer, MESH_V2_LOST_REASON_OVERFLOW);
			return ESP_ERR_NO_MEM;
		}
	}
	record_lost(ctx, peer, lost->channel_id, lost->reason,
		    lost->seq_first, lost->seq_last, lost_count);
	return ESP_OK;
}

esp_err_t keemash_rel_handle_rx(keemash_rel_ctx_t *ctx, const uint8_t from[6],
				const void *packet, size_t packet_len)
{
	if (!ctx || !from) return ESP_ERR_INVALID_ARG;
	const mesh_v2_hdr_t *h = NULL;
	const uint8_t *payload = NULL;
	if (!packet_valid(packet, packet_len, &h, &payload)) {
		return ESP_ERR_INVALID_CRC;
	}
	if (!mac_eq(h->src_mac, from)) {
		return ESP_ERR_INVALID_ARG;
	}
	switch (h->type) {
	case MESH_V2_TYPE_RELIABLE_HELLO:
		if (h->payload_len < sizeof(mesh_v2_reliable_hello_payload_t))
			return ESP_ERR_INVALID_SIZE;
		return handle_hello(ctx, from,
			(const mesh_v2_reliable_hello_payload_t *)payload);
	case MESH_V2_TYPE_RELIABLE_HELLO_ACK:
		if (h->payload_len < sizeof(mesh_v2_reliable_hello_ack_payload_t))
			return ESP_ERR_INVALID_SIZE;
		return handle_hello_ack(ctx, from,
			(const mesh_v2_reliable_hello_ack_payload_t *)payload);
	case MESH_V2_TYPE_RELIABLE_DATA: {
		if (h->payload_len < sizeof(mesh_v2_reliable_hdr_t))
			return ESP_ERR_INVALID_SIZE;
		const mesh_v2_reliable_hdr_t *rh =
			(const mesh_v2_reliable_hdr_t *)payload;
		return handle_data(ctx, from, rh, payload + sizeof(*rh),
				   h->payload_len - sizeof(*rh));
	}
	case MESH_V2_TYPE_RELIABLE_ACK:
	case MESH_V2_TYPE_RELIABLE_NACK:
		if (h->payload_len < sizeof(mesh_v2_reliable_ack_payload_t))
			return ESP_ERR_INVALID_SIZE;
		return handle_ack_packet(ctx, from,
			(const mesh_v2_reliable_ack_payload_t *)payload,
			h->type == MESH_V2_TYPE_RELIABLE_NACK);
	case MESH_V2_TYPE_RELIABLE_LOST:
		if (h->payload_len < sizeof(mesh_v2_reliable_lost_payload_t))
			return ESP_ERR_INVALID_SIZE;
		return handle_lost_packet(ctx, from,
			(const mesh_v2_reliable_lost_payload_t *)payload);
	default:
		return ESP_ERR_NOT_SUPPORTED;
	}
}

void keemash_rel_poll(keemash_rel_ctx_t *ctx)
{
	if (!ctx) return;
	uint32_t now = now_ms();
	flush_delayed_packet(ctx, now);
	for (int priority = KEEMASH_REL_PRIORITY_CONTROL;
	     priority >= KEEMASH_REL_PRIORITY_LOG; priority--) {
		for (uint16_t i = 0; i < ctx->cfg.tx_slots; i++) {
			tx_slot_t *slot = &ctx->tx[i];
			if (!slot->used || slot->priority != priority) continue;
			peer_state_t *peer = peer_find(ctx, slot->peer, false);
			if (!peer || !peer->ready) continue;
			if ((uint32_t)(now - slot->last_sent_ms) < peer->rto_ms) continue;
			if (slot->retries >= ctx->cfg.max_retries) {
				uint8_t ch = slot->channel;
				uint32_t seq = slot->seq;
				(void)send_lost_packet(ctx, peer, ch,
						      MESH_V2_LOST_REASON_RETRY_EXHAUSTED,
						      0, seq, seq);
				clear_peer_buffers(ctx, peer,
						   MESH_V2_LOST_REASON_RETRY_EXHAUSTED);
				if (ctx->cfg.root_role) {
					peer->node_session_id = 0;
				} else {
					peer->root_session_id = 0;
				}
				goto tx_poll_done;
			}
			(void)retransmit_slot(ctx, peer, slot);
		}
	}
tx_poll_done:
	for (uint16_t i = 0; i < ctx->cfg.reassembly_slots; i++) {
		reassembly_slot_t *slot = &ctx->reassembly[i];
		if (!slot->used ||
		    (uint32_t)(now - slot->last_ms) < ctx->cfg.fragment_timeout_ms) {
			continue;
		}
		peer_state_t *peer = peer_find(ctx, slot->peer, false);
		if (peer) {
			uint32_t last = slot->first_seq + slot->fragment_count - 1U;
			record_lost(ctx, peer, slot->channel,
				    MESH_V2_LOST_REASON_FRAGMENT_TIMEOUT,
				    slot->first_seq, last, slot->fragment_count);
			(void)send_lost_packet(ctx, peer, slot->channel,
					      MESH_V2_LOST_REASON_FRAGMENT_TIMEOUT,
					      MESH_V2_LOST_FLAG_RECEIVER_DROP,
					      slot->first_seq, last);
		}
		memset(slot, 0, sizeof(*slot));
	}
}

void keemash_rel_reset_peer(keemash_rel_ctx_t *ctx, const uint8_t peer_mac[6],
			    uint8_t reason)
{
	if (!ctx) return;
	peer_state_t *peer = peer_find(ctx, peer_mac, false);
	if (peer) clear_peer_buffers(ctx, peer, reason);
}

bool keemash_rel_peer_ready(keemash_rel_ctx_t *ctx, const uint8_t peer_mac[6])
{
	if (!ctx) return false;
	peer_state_t *peer = peer_find(ctx, peer_mac, false);
	return peer && peer->ready;
}

bool keemash_rel_stats(keemash_rel_ctx_t *ctx, const uint8_t peer_mac[6],
		       keemash_rel_stats_t *out)
{
	if (!ctx || !out) return false;
	memset(out, 0, sizeof(*out));
	peer_state_t *peer = peer_find(ctx, peer_mac, false);
	if (!peer) return false;
	uint32_t now = now_ms();
	out->seen = true;
	out->ready = peer->ready;
	out->root_session_id = peer->root_session_id;
	out->node_session_id = peer->node_session_id;
	out->tx_unacked = tx_unacked(ctx, peer);
	out->reorder_depth = rx_depth(ctx, peer);
	out->rto_ms = peer->rto_ms;
	out->retry_count = peer->retry_count;
	out->ack_age_ms = peer->last_ack_ms ? now - peer->last_ack_ms : UINT32_MAX;
	out->rtt_ms = peer->srtt_ms;
	out->overflow_count = peer->overflow_count;
	out->replay_count = peer->replay_count;
	out->lost_count = peer->lost_count;
	out->lost_reason = peer->lost_reason;
	return true;
}
