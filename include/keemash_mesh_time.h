// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <stddef.h>

#include "esp_err.h"
#include "keemash_mesh_proto.h"

#ifdef __cplusplus
extern "C" {
#endif

// Initialize the process timezone used by local logs. Pass NULL to leave TZ unchanged.
void keemash_mesh_time_init(const char *tz_rule);

// Compatibility parser for the legacy type-2 TIME packet.
esp_err_t keemash_mesh_time_handle_v1(const void *packet, size_t packet_len);

// Apply an authenticated typed V2 TIME payload using latest-generation semantics.
esp_err_t keemash_mesh_time_apply_v2(const mesh_v2_time_payload_t *time_sync);

#ifdef __cplusplus
}
#endif
