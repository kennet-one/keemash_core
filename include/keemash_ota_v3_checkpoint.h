// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <stdint.h>

#include "esp_err.h"
#include "keemash_ota_v3.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KEEMASH_OTA_V3_SIGNED_FIELDS_MAX 1024U

typedef struct {
	uint8_t operation_id[16];
	uint8_t artifact_id[KEEMASH_OTA_V3_SHA256_LEN];
	uint8_t signature[KEEMASH_OTA_V3_SIGNATURE_LEN];
	uint16_t signed_fields_len;
	uint8_t signed_fields[KEEMASH_OTA_V3_SIGNED_FIELDS_MAX];
	char partition_label[17];
	keemash_ota_v3_resume_point_t resume;
} keemash_ota_v3_checkpoint_t;

/* The caller must initialize default NVS before using these functions. */
esp_err_t keemash_ota_v3_checkpoint_load(
	keemash_ota_v3_checkpoint_t *checkpoint);

esp_err_t keemash_ota_v3_checkpoint_save(
	const keemash_ota_v3_checkpoint_t *checkpoint);

/* A newer tombstone prevents an old checkpoint from being resumed. */
esp_err_t keemash_ota_v3_checkpoint_clear(void);

#ifdef __cplusplus
}
#endif
