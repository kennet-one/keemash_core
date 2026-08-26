// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "keemash_mesh_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

// Initialize the process timezone used by local logs. Pass NULL to leave TZ unchanged.
void keemash_mesh_time_init(const char *tz_rule);

typedef struct {
	bool synchronized;
	bool last_rx_v2;
	uint32_t generation;
	uint32_t source_uptime_s;
	uint32_t last_sync_age_ms;
} keemash_mesh_time_status_t;

// Compatibility parser for the legacy type-2 TIME packet.
esp_err_t keemash_mesh_time_handle_v1(const void *packet, size_t packet_len);

// Apply an authenticated typed V2 TIME payload using latest-generation semantics.
esp_err_t keemash_mesh_time_apply_v2(const mesh_v2_time_payload_t *time_sync);

// Return synchronization metadata without changing the system clock.
void keemash_mesh_time_get_status(keemash_mesh_time_status_t *status);

#ifdef __cplusplus
}
#endif
