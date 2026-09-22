// SPDX-License-Identifier: GPL-2.0-only

#include "keemash_ota_v3_boot.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_ota_ops.h"
#include "keemash_ota_v3_checkpoint.h"

static uint64_t read_be64(const uint8_t bytes[8])
{
	uint64_t value = 0U;
	for (size_t i = 0; i < 8U; ++i) value = (value << 8U) | bytes[i];
	return value;
}

static void copy_operation(const uint8_t bytes[16],
	keemash_fabric_v2_Id128 *id)
{
	id->high = read_be64(bytes);
	id->low = read_be64(bytes + 8U);
}

static bool report_terminal(keemash_fabric_v2_OtaBootState state)
{
	return state == keemash_fabric_v2_OtaBootState_OTA_BOOT_VALIDATED ||
		state == keemash_fabric_v2_OtaBootState_OTA_BOOT_ROLLED_BACK ||
		state == keemash_fabric_v2_OtaBootState_OTA_BOOT_FAILED;
}

esp_err_t keemash_ota_v3_boot_report(
	const keemash_fabric_v2_Id128 *node_id, uint64_t boot_session,
	keemash_fabric_v2_OtaBootReport *report)
{
	if (!node_id || !report) return ESP_ERR_INVALID_ARG;
	keemash_ota_v3_checkpoint_t *checkpoint = calloc(1U, sizeof(*checkpoint));
	if (!checkpoint) return ESP_ERR_NO_MEM;
	esp_err_t err = keemash_ota_v3_checkpoint_load(checkpoint);
	if (err != ESP_OK) {
		free(checkpoint);
		return err;
	}
	if (checkpoint->phase != KEEMASH_OTA_V3_CHECKPOINT_BOOT_PENDING) {
		free(checkpoint);
		return ESP_ERR_NOT_FOUND;
	}
	keemash_ota_v3_signed_fields_t fields;
	err = keemash_ota_v3_verify_signed_fields(checkpoint->signed_fields,
		checkpoint->signed_fields_len, checkpoint->signature,
		KEEMASH_OTA_V3_SIGNATURE_LEN, &fields);
	if (err != ESP_OK) {
		free(checkpoint);
		return err;
	}
	*report = (keemash_fabric_v2_OtaBootReport)
		keemash_fabric_v2_OtaBootReport_init_zero;
	report->has_operation_id = true;
	copy_operation(checkpoint->operation_id, &report->operation_id);
	report->has_node_id = true;
	report->node_id = *node_id;
	report->artifact_id.size = KEEMASH_OTA_V3_SHA256_LEN;
	memcpy(report->artifact_id.bytes, checkpoint->artifact_id,
	       KEEMASH_OTA_V3_SHA256_LEN);
	report->boot_session = boot_session;
	strncpy(report->firmware_version, fields.firmware_version,
		sizeof(report->firmware_version) - 1U);

	const esp_partition_t *running = esp_ota_get_running_partition();
	if (!running || strcmp(running->label, checkpoint->partition_label) != 0) {
		report->state =
			keemash_fabric_v2_OtaBootState_OTA_BOOT_ROLLED_BACK;
		strncpy(report->message, "target partition is not running",
			sizeof(report->message) - 1U);
		free(checkpoint);
		return ESP_OK;
	}
	esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
	err = esp_ota_get_state_partition(running, &state);
	report->rollback_state = (uint32_t)state;
	if (err != ESP_OK) {
		report->state = keemash_fabric_v2_OtaBootState_OTA_BOOT_FAILED;
		report->health_status = (uint32_t)err;
		strncpy(report->message, "rollback state unavailable",
			sizeof(report->message) - 1U);
	} else if (state == ESP_OTA_IMG_VALID) {
		report->state = keemash_fabric_v2_OtaBootState_OTA_BOOT_VALIDATED;
		strncpy(report->message, "image validated",
			sizeof(report->message) - 1U);
	} else if (state == ESP_OTA_IMG_NEW ||
		   state == ESP_OTA_IMG_PENDING_VERIFY) {
		report->state =
			keemash_fabric_v2_OtaBootState_OTA_BOOT_PENDING_VERIFY;
		strncpy(report->message, "waiting for application health",
			sizeof(report->message) - 1U);
	} else {
		report->state = keemash_fabric_v2_OtaBootState_OTA_BOOT_FAILED;
		report->health_status = (uint32_t)ESP_FAIL;
		snprintf(report->message, sizeof(report->message),
			"unexpected OTA state %u", (unsigned)state);
	}
	free(checkpoint);
	return ESP_OK;
}

esp_err_t keemash_ota_v3_boot_ack(
	const keemash_fabric_v2_OtaBootAck *ack)
{
	if (!ack || !ack->has_operation_id ||
	    ack->artifact_id.size != KEEMASH_OTA_V3_SHA256_LEN ||
	    !report_terminal(ack->state)) return ESP_ERR_INVALID_ARG;
	keemash_fabric_v2_Id128 no_node = {0};
	keemash_fabric_v2_OtaBootReport report;
	esp_err_t err = keemash_ota_v3_boot_report(&no_node, 0U, &report);
	if (err != ESP_OK) return err;
	if (report.operation_id.high != ack->operation_id.high ||
	    report.operation_id.low != ack->operation_id.low ||
	    report.artifact_id.size != ack->artifact_id.size ||
	    memcmp(report.artifact_id.bytes, ack->artifact_id.bytes,
		   ack->artifact_id.size) != 0 || report.state != ack->state) {
		return ESP_ERR_INVALID_STATE;
	}
	return keemash_ota_v3_checkpoint_clear();
}
