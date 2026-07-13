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

// Transport/local hooks. Firmware provides strong definitions.
esp_err_t keemash_mesh_transport_send(const uint8_t dst[6], const void *packet, size_t packet_len);
void keemash_mesh_get_local_mac(uint8_t mac[6]);

// Root application hooks. Default weak implementations are no-ops.
void keemash_mesh_root_on_node_seen_uptime(const uint8_t mac[6], const char *tag,
                                           bool uptime_valid, uint32_t uptime_s);
void keemash_mesh_root_on_node_seen(const uint8_t mac[6], const char *tag);
void keemash_mesh_root_on_log_line(const uint8_t mac[6], const char *tag, const char *line);
void keemash_mesh_root_on_task_snapshot(const uint8_t mac[6],
                                        const mesh_v2_task_snapshot_payload_t *snapshot);
void keemash_mesh_root_on_memory_snapshot(const uint8_t mac[6],
                                          const mesh_v2_memory_payload_t *snapshot);
void keemash_mesh_root_on_ota_status(const uint8_t mac[6],
                                     const mesh_v2_ota_status_payload_t *status,
                                     size_t status_len);
void keemash_mesh_root_on_topology(const uint8_t mac[6], const void *payload, size_t payload_len);
void keemash_mesh_root_on_control_event(const char *text);
void keemash_mesh_root_on_control(const uint8_t peer[6], uint32_t root_session,
				  uint32_t node_session, uint8_t kind,
				  uint32_t command_id, uint8_t status,
				  const char *text);
void keemash_mesh_root_on_state_changed(void);

// Node application hooks. Default weak implementations keep unsupported behavior safe.
bool keemash_mesh_node_on_control_command_result(const char *text, uint8_t *status,
                                                 char *result, size_t result_size);
bool keemash_mesh_node_on_control_command(const char *text);
void keemash_mesh_node_on_log_ctrl(bool enable);
uint32_t keemash_mesh_node_v1_ok_age_ms(void);
bool keemash_mesh_node_log_stream_enabled(void);
void keemash_mesh_node_on_time_sync(const mesh_v2_time_payload_t *time_sync);

#ifdef __cplusplus
}
#endif
