// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

// Call once during startup, after log_time_vprintf_start().
esp_err_t keemash_mesh_log_stream_init(const char *tag);

// Call when the node is actually connected to mesh (PARENT_CONNECTED).
void keemash_mesh_log_stream_on_mesh_connected(void);
void keemash_mesh_log_stream_on_mesh_disconnected(void);

// Shared mesh send gate for node-to-root binary packets.
esp_err_t keemash_mesh_log_stream_send_bin_to_root(const void *packet, size_t packet_len);
bool keemash_mesh_log_stream_transport_ready(void);

// Best-effort immediate NODEINFO beacon used by recovery watchdogs.
esp_err_t keemash_mesh_log_stream_send_nodeinfo_now(void);
void keemash_mesh_log_stream_kick_nodeinfo_burst(void);
esp_err_t keemash_mesh_log_stream_last_send_err(void);
uint32_t keemash_mesh_log_stream_tx_accepted_age_ms(void);
bool keemash_mesh_log_stream_tx_accepted_fresh(uint32_t max_age_ms);
void keemash_mesh_log_stream_clear_tx_accepted(void);
bool keemash_mesh_log_stream_enabled(void);

// Call from mesh_rx_task() when MESH_LOG_TYPE_CTRL is received.
esp_err_t keemash_mesh_log_stream_handle_v1_ctrl(const void *pkt_buf, size_t pkt_len);

#ifdef __cplusplus
}
#endif
