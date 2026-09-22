// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <stdint.h>

#include "esp_err.h"
#include "keemash_ota_v3.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Returns ESP_ERR_NOT_FOUND when no v3 boot attestation is pending. */
esp_err_t keemash_ota_v3_boot_report(
	const keemash_fabric_v2_Id128 *node_id, uint64_t boot_session,
	keemash_fabric_v2_OtaBootReport *report);

/* Clears the persistent report only after an exact terminal-state ACK. */
esp_err_t keemash_ota_v3_boot_ack(
	const keemash_fabric_v2_OtaBootAck *ack);

#ifdef __cplusplus
}
#endif
