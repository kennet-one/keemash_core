// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "keemash_mesh_core.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
	bool seen;
	uint8_t peer_mac[6];
	uint32_t command_id;
	uint32_t root_session_id;
	uint32_t node_session_id;
	uint8_t status;
	uint32_t seen_count;
	uint32_t updated_ms;
	char text[64];
	char first_text[64];
	bool text_changed;
} mesh_v2_command_result_t;
typedef struct {
	bool seen;
	bool tunnel_seen;
	bool has_gap;
	uint32_t session_id;
	uint32_t expected_seq;
	uint32_t gap_count;
	uint32_t replay_count;
	uint32_t lost_count;
	uint32_t last_v2_ms;
	uint32_t last_tunnel_ms;
	uint32_t last_rel_log_ms;
	uint32_t last_ack_tx_ms;
	int32_t last_ack_err;
	bool reliable_ready;
	uint32_t root_session_id;
	uint32_t node_session_id;
	uint32_t tx_unacked;
	uint32_t reorder_depth;
	uint32_t rto_ms;
	uint32_t retry_count;
	uint32_t ack_age_ms;
	uint32_t rtt_ms;
	uint32_t overflow_count;
	uint8_t lost_reason;
	uint32_t capabilities;
	bool route_up;
	uint32_t route_down_age_ms;
	uint32_t duplicate_tag_count;
	uint32_t time_superseded_count;
} mesh_v2_root_stats_t;

esp_err_t mesh_v2_root_init(void);
esp_err_t mesh_v2_root_handle_rx(const uint8_t from[6], const void *pkt_buf, size_t pkt_len);
bool mesh_v2_root_stats_for_mac(const uint8_t mac[6], mesh_v2_root_stats_t *out);
bool mesh_v2_root_tunnel_ready_for_mac(const uint8_t mac[6]);
esp_err_t mesh_v2_root_send_log_ctrl(const uint8_t mac[6], bool enable);
esp_err_t mesh_v2_root_send_task_request(const uint8_t mac[6], uint32_t request_id);
esp_err_t mesh_v2_root_send_ota_payload(const uint8_t mac[6],
                                        const void *payload,
                                        size_t payload_len);
esp_err_t mesh_v2_root_send_command(const uint8_t mac[6], uint32_t command_id,
				    const char *command);
bool mesh_v2_root_command_result(uint32_t command_id,
					 mesh_v2_command_result_t *out);
bool mesh_v2_root_command_result_for_peer(const uint8_t mac[6], uint32_t command_id,
					  mesh_v2_command_result_t *out);
uint32_t mesh_v2_root_next_command_id(void);
bool mesh_v2_root_find_ready_by_tag(const char *tag, uint8_t mac[6]);
bool mesh_v2_root_find_lossless_by_tag(const char *tag, uint8_t mac[6],
				       uint32_t required_caps);
bool mesh_v2_root_peer_advertises_lossless(const uint8_t mac[6],
					   uint32_t required_caps);
bool mesh_v2_root_peer_lossless(const uint8_t mac[6], uint32_t required_caps);
esp_err_t mesh_v2_root_queue_time(const uint8_t mac[6], uint32_t generation,
				  int64_t epoch_sec, uint32_t source_uptime_s);
size_t mesh_v2_root_queue_time_all(uint32_t generation, int64_t epoch_sec,
				   uint32_t source_uptime_s);
void mesh_v2_root_sync_routes(const uint8_t *macs, size_t count);

#ifdef __cplusplus
}
#endif
