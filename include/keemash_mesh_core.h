// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "keemash_mesh_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KEEMASH_REL_PRIORITY_LOG	0
#define KEEMASH_REL_PRIORITY_NORMAL	1
#define KEEMASH_REL_PRIORITY_HIGH	2
#define KEEMASH_REL_PRIORITY_CONTROL	3

typedef struct keemash_rel_ctx keemash_rel_ctx_t;

typedef esp_err_t (*keemash_rel_send_fn)(void *user, const uint8_t dst[6],
					 const void *packet, size_t packet_len);
typedef void (*keemash_rel_deliver_fn)(void *user, const uint8_t peer[6],
				      uint8_t channel, const void *payload,
				      size_t payload_len, uint32_t stream_id);
typedef void (*keemash_rel_event_fn)(void *user, const uint8_t peer[6],
				    uint8_t channel, uint8_t reason,
				    uint32_t seq_first, uint32_t seq_last);

typedef struct {
	bool root_role;
	uint8_t local_mac[6];
	uint16_t max_peers;
	uint16_t tx_slots;
	uint16_t rx_slots;
	uint16_t reassembly_slots;
	uint16_t reserved_control_slots;
	uint32_t initial_rto_ms;
	uint32_t min_rto_ms;
	uint32_t max_rto_ms;
	uint32_t fragment_timeout_ms;
	uint8_t max_retries;
	uint16_t fault_drop_data_every;
	uint16_t fault_drop_ack_every;
	uint16_t fault_drop_nack_every;
	uint16_t fault_duplicate_every;
	uint16_t fault_delay_every;
	uint16_t fault_delay_ms;
	uint16_t fault_reorder_every;
	uint16_t fault_overflow_every;
	keemash_rel_send_fn send;
	keemash_rel_deliver_fn deliver;
	keemash_rel_event_fn event;
	void *user;
} keemash_rel_config_t;

#define KEEMASH_REL_DEBUG_CASE_SEQ_WRAP		0x00000001UL
#define KEEMASH_REL_DEBUG_CASE_SESSION_RESET	0x00000002UL
#define KEEMASH_REL_DEBUG_CASE_FRAGMENT_TIMEOUT	0x00000004UL
#define KEEMASH_REL_DEBUG_CASE_RETRY_EXHAUSTED	0x00000008UL
#define KEEMASH_REL_DEBUG_CASE_ALL		( \
	KEEMASH_REL_DEBUG_CASE_SEQ_WRAP | \
	KEEMASH_REL_DEBUG_CASE_SESSION_RESET | \
	KEEMASH_REL_DEBUG_CASE_FRAGMENT_TIMEOUT | \
	KEEMASH_REL_DEBUG_CASE_RETRY_EXHAUSTED)

typedef struct {
	bool pass;
	uint32_t cases_run;
	uint32_t cases_passed;
	uint32_t failed_mask;
	uint32_t lost_count;
	uint32_t overflow_count;
	uint32_t replay_count;
	uint32_t retry_count;
	char message[128];
} keemash_rel_debug_result_t;
typedef struct {
	bool seen;
	bool ready;
	uint32_t root_session_id;
	uint32_t node_session_id;
	uint32_t tx_unacked;
	uint32_t reorder_depth;
	uint32_t rto_ms;
	uint32_t retry_count;
	uint32_t ack_age_ms;
	uint32_t rtt_ms;
	uint32_t overflow_count;
	uint32_t replay_count;
	uint32_t lost_count;
	uint8_t lost_reason;
} keemash_rel_stats_t;

esp_err_t keemash_rel_init(keemash_rel_ctx_t **out, const keemash_rel_config_t *config);
void keemash_rel_deinit(keemash_rel_ctx_t *ctx);
uint32_t keemash_rel_local_session(const keemash_rel_ctx_t *ctx);

esp_err_t keemash_rel_send_hello(keemash_rel_ctx_t *ctx, const uint8_t peer[6],
				 const char *tag, uint32_t uptime_s,
				 uint32_t capabilities);
esp_err_t keemash_rel_send(keemash_rel_ctx_t *ctx, const uint8_t peer[6],
			   uint8_t channel, const void *payload, size_t payload_len,
			   uint8_t priority);
esp_err_t keemash_rel_handle_rx(keemash_rel_ctx_t *ctx, const uint8_t from[6],
				const void *packet, size_t packet_len);
void keemash_rel_poll(keemash_rel_ctx_t *ctx);
void keemash_rel_reset_peer(keemash_rel_ctx_t *ctx, const uint8_t peer[6],
			    uint8_t reason);
bool keemash_rel_peer_ready(keemash_rel_ctx_t *ctx, const uint8_t peer[6]);
bool keemash_rel_stats(keemash_rel_ctx_t *ctx, const uint8_t peer[6],
		       keemash_rel_stats_t *out);
esp_err_t keemash_rel_debug_force_next_seq(keemash_rel_ctx_t *ctx,
						   const uint8_t peer_mac[6],
						   uint8_t channel,
						   uint32_t next_seq);
esp_err_t keemash_rel_debug_force_expected_seq(keemash_rel_ctx_t *ctx,
						       const uint8_t peer_mac[6],
						       uint8_t channel,
						       uint32_t expected_seq);
esp_err_t keemash_rel_debug_reset_local_session(keemash_rel_ctx_t *ctx);
esp_err_t keemash_rel_debug_force_fragment_timeout(keemash_rel_ctx_t *ctx,
						       const uint8_t peer_mac[6],
						       uint8_t channel);
esp_err_t keemash_rel_debug_force_retry_exhausted(keemash_rel_ctx_t *ctx,
						      const uint8_t peer_mac[6],
						      uint8_t channel);
esp_err_t keemash_rel_debug_run_selftest(uint32_t case_mask,
						 keemash_rel_debug_result_t *out);

#ifdef __cplusplus
}
#endif
