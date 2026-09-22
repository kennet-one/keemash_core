// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "esp_err.h"
#include "keemash_ota_v3_flash_receiver.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	keemash_ota_v3_preflight_fn preflight;
	void *preflight_context;
	uint32_t reboot_delay_ms;
} keemash_mesh_ota_v3_config_t;

esp_err_t keemash_mesh_ota_v3_receiver_start(
	const keemash_mesh_ota_v3_config_t *config);
esp_err_t keemash_mesh_ota_v3_receiver_handle(
	const void *payload, size_t payload_len);
bool keemash_mesh_ota_v3_receiver_active(void);

#ifdef __cplusplus
}
#endif
