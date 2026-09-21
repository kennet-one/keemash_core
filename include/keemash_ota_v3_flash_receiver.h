// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "esp_partition.h"
#include "keemash_ota_v3.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct keemash_ota_v3_flash_receiver keemash_ota_v3_flash_receiver_t;

typedef esp_err_t (*keemash_ota_v3_preflight_fn)(void *context);

typedef struct {
	uint32_t raw_offset;
	uint32_t encoded_offset;
	uint32_t next_block_index;
	bool active;
	bool verified;
	bool resumed;
} keemash_ota_v3_flash_status_t;

/* Caller serializes all calls on one OTA worker and excludes OTA v1/v2. */
esp_err_t keemash_ota_v3_flash_receiver_create(
	keemash_ota_v3_flash_receiver_t **out);

esp_err_t keemash_ota_v3_flash_receiver_prepare(
	keemash_ota_v3_flash_receiver_t *receiver,
	const uint8_t operation_id[16],
	const uint8_t artifact_id[KEEMASH_OTA_V3_SHA256_LEN],
	const uint8_t *signed_fields, size_t signed_fields_len,
	const uint8_t signature[KEEMASH_OTA_V3_SIGNATURE_LEN],
	const char *project_name, const char *chip_target,
	uint32_t core_version, uint32_t fabric_schema,
	keemash_ota_v3_preflight_fn preflight, void *preflight_context);

esp_err_t keemash_ota_v3_flash_receiver_write(
	keemash_ota_v3_flash_receiver_t *receiver,
	const keemash_fabric_v2_FirmwareBlockDescriptor *descriptor,
	uint32_t block_encoded_offset, const uint8_t *chunk,
	size_t chunk_size, bool final_chunk);

/* Verifies the complete image and closes the OTA handle; never changes boot. */
esp_err_t keemash_ota_v3_flash_receiver_verify(
	keemash_ota_v3_flash_receiver_t *receiver,
	const esp_partition_t **verified_partition);

esp_err_t keemash_ota_v3_flash_receiver_abort(
	keemash_ota_v3_flash_receiver_t *receiver,
	const uint8_t operation_id[16],
	const uint8_t artifact_id[KEEMASH_OTA_V3_SHA256_LEN]);

void keemash_ota_v3_flash_receiver_status(
	const keemash_ota_v3_flash_receiver_t *receiver,
	keemash_ota_v3_flash_status_t *status);

void keemash_ota_v3_flash_receiver_destroy(
	keemash_ota_v3_flash_receiver_t *receiver);

#ifdef __cplusplus
}
#endif
