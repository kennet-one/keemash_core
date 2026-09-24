// SPDX-License-Identifier: GPL-2.0-only

#include "keemash_mesh_ota_v3_receiver.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_app_desc.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "keemash_mesh_node.h"
#include "keemash_ota_v3_boot.h"
#include "sdkconfig.h"

#define OTA_V3_QUEUE_LEN 2U
#define OTA_V3_WORKER_STACK 8192U
#define OTA_V3_WORKER_PRIO 5U
#define OTA_V3_REPORT_PERIOD_MS 30000U
#define OTA_V3_IDLE_TIMEOUT_MS (10U * 60U * 1000U)

typedef struct {
	uint16_t length;
	uint8_t bytes[keemash_fabric_v2_OtaMeshMessage_size];
} ota_v3_work_item_t;

#if CONFIG_KEEMASH_OTA_V3_ENABLE
static const char *TAG = "ota_v3_rx";
static keemash_mesh_ota_v3_config_t s_config;
static keemash_ota_v3_flash_receiver_t *s_receiver;
static QueueHandle_t s_queue;
static SemaphoreHandle_t s_lock;
static TaskHandle_t s_worker;

static const keemash_fabric_v2_Id128 *message_operation(
	const keemash_fabric_v2_OtaTransfer *transfer)
{
	switch (transfer->which_body) {
	case keemash_fabric_v2_OtaTransfer_prepare_tag:
		return transfer->body.prepare.has_operation_id ?
			&transfer->body.prepare.operation_id : NULL;
	case keemash_fabric_v2_OtaTransfer_data_tag:
		return transfer->body.data.has_operation_id ?
			&transfer->body.data.operation_id : NULL;
	case keemash_fabric_v2_OtaTransfer_commit_tag:
		return transfer->body.commit.has_operation_id ?
			&transfer->body.commit.operation_id : NULL;
	case keemash_fabric_v2_OtaTransfer_abort_tag:
		return transfer->body.abort.has_operation_id ?
			&transfer->body.abort.operation_id : NULL;
	case keemash_fabric_v2_OtaTransfer_query_tag:
		return transfer->body.query.has_operation_id ?
			&transfer->body.query.operation_id : NULL;
	default:
		return NULL;
	}
}

static bool message_artifact(const keemash_fabric_v2_OtaTransfer *transfer,
	uint8_t artifact_id[KEEMASH_OTA_V3_SHA256_LEN])
{
	const uint8_t *bytes = NULL;
	size_t size = 0U;
	switch (transfer->which_body) {
	case keemash_fabric_v2_OtaTransfer_prepare_tag:
		size = transfer->body.prepare.artifact_id.size;
		bytes = transfer->body.prepare.artifact_id.bytes;
		break;
	case keemash_fabric_v2_OtaTransfer_data_tag:
		size = transfer->body.data.artifact_id.size;
		bytes = transfer->body.data.artifact_id.bytes;
		break;
	case keemash_fabric_v2_OtaTransfer_commit_tag:
		size = transfer->body.commit.artifact_id.size;
		bytes = transfer->body.commit.artifact_id.bytes;
		break;
	case keemash_fabric_v2_OtaTransfer_abort_tag:
		size = transfer->body.abort.artifact_id.size;
		bytes = transfer->body.abort.artifact_id.bytes;
		break;
	case keemash_fabric_v2_OtaTransfer_query_tag:
		size = transfer->body.query.artifact_id.size;
		bytes = transfer->body.query.artifact_id.bytes;
		break;
	default:
		return false;
	}
	if (!bytes || size != KEEMASH_OTA_V3_SHA256_LEN) return false;
	memcpy(artifact_id, bytes, KEEMASH_OTA_V3_SHA256_LEN);
	return true;
}

static esp_err_t send_status(const keemash_fabric_v2_OtaTransfer *request,
	keemash_fabric_v2_OtaPhase phase, esp_err_t result, const char *text)
{
	const keemash_fabric_v2_Id128 *operation = message_operation(request);
	uint8_t artifact_id[KEEMASH_OTA_V3_SHA256_LEN];
	if (!operation || !message_artifact(request, artifact_id))
		return ESP_ERR_INVALID_ARG;
	keemash_fabric_v2_OtaMeshMessage *message =
		calloc(1U, sizeof(*message));
	if (!message) return ESP_ERR_NO_MEM;
	message->which_body = keemash_fabric_v2_OtaMeshMessage_transfer_tag;
	keemash_fabric_v2_OtaTransfer *transfer = &message->body.transfer;
	transfer->which_body = keemash_fabric_v2_OtaTransfer_status_tag;
	keemash_fabric_v2_OtaTransferStatus *status = &transfer->body.status;
	status->has_operation_id = true;
	status->operation_id = *operation;
	status->artifact_id.size = KEEMASH_OTA_V3_SHA256_LEN;
	memcpy(status->artifact_id.bytes, artifact_id,
	       KEEMASH_OTA_V3_SHA256_LEN);
	status->phase = phase;
	status->status = (uint32_t)result;
	status->window_credit = CONFIG_KEEMASH_OTA_V3_MAX_WINDOW;
	keemash_ota_v3_flash_status_t flash = {0};
	keemash_ota_v3_flash_receiver_status(s_receiver, &flash);
	status->raw_offset = flash.raw_offset;
	status->encoded_offset = flash.encoded_offset;
	status->next_block_index = flash.next_block_index;
	status->resume_count = flash.resumed ? 1U : 0U;
	if (text) {
		strncpy(status->message, text, sizeof(status->message) - 1U);
	}
	esp_err_t err = mesh_v2_node_send_ota_v3_message(message);
	free(message);
	return err;
}

static esp_err_t send_pending_boot_report(void)
{
	if (!mesh_v2_node_reliable_ready()) return ESP_ERR_INVALID_STATE;
	keemash_fabric_id_t node_id;
	uint64_t boot_session = 0U;
	esp_err_t err = mesh_v2_node_fabric_identity(&node_id, &boot_session);
	if (err != ESP_OK) return err;
	keemash_fabric_v2_OtaMeshMessage *message =
		calloc(1U, sizeof(*message));
	if (!message) return ESP_ERR_NO_MEM;
	message->which_body = keemash_fabric_v2_OtaMeshMessage_boot_report_tag;
	err = keemash_ota_v3_boot_report(&node_id, boot_session,
		&message->body.boot_report);
	if (err == ESP_OK) err = mesh_v2_node_send_ota_v3_message(message);
	free(message);
	return err;
}

static void reboot_after_status(void)
{
	uint32_t delay = s_config.reboot_delay_ms ?
		s_config.reboot_delay_ms : 1500U;
	vTaskDelay(pdMS_TO_TICKS(delay));
	esp_restart();
}

static void process_message(keemash_fabric_v2_OtaMeshMessage *message)
{
	if (message->which_body ==
	    keemash_fabric_v2_OtaMeshMessage_boot_ack_tag) {
		(void)keemash_ota_v3_boot_ack(&message->body.boot_ack);
		return;
	}
	if (message->which_body !=
	    keemash_fabric_v2_OtaMeshMessage_transfer_tag) return;
	keemash_fabric_v2_OtaTransfer *transfer = &message->body.transfer;
	if (transfer->which_body == keemash_fabric_v2_OtaTransfer_query_tag &&
	    send_pending_boot_report() == ESP_OK) return;
	if (transfer->which_body == keemash_fabric_v2_OtaTransfer_commit_tag)
		(void)send_status(transfer,
			keemash_fabric_v2_OtaPhase_OTA_PHASE_VERIFYING,
			ESP_OK, "verifying image");
	const esp_app_desc_t *app = esp_app_get_description();
	const char *project = app ? app->project_name : "";
	const esp_partition_t *verified = NULL;
	esp_err_t err = keemash_ota_v3_flash_receiver_handle_transfer(
		s_receiver, transfer, project, CONFIG_IDF_TARGET,
		KEEMASH_MESH_CORE_VERSION, KEEMASH_FABRIC_VERSION,
		s_config.preflight, s_config.preflight_context, &verified);
	if (err != ESP_OK) {
		(void)send_status(transfer,
			keemash_fabric_v2_OtaPhase_OTA_PHASE_FAILED, err,
			esp_err_to_name(err));
		return;
	}
	if (verified) {
		err = keemash_ota_v3_flash_receiver_activate(s_receiver,
			s_config.preflight, s_config.preflight_context);
		if (err != ESP_OK) {
			(void)send_status(transfer,
				keemash_fabric_v2_OtaPhase_OTA_PHASE_FAILED,
				err, esp_err_to_name(err));
			return;
		}
		err = send_status(transfer,
			keemash_fabric_v2_OtaPhase_OTA_PHASE_REBOOTING,
			ESP_OK, "verified; rebooting");
		if (err != ESP_OK) return;
		reboot_after_status();
		return;
	}
	keemash_fabric_v2_OtaPhase phase =
		transfer->which_body == keemash_fabric_v2_OtaTransfer_abort_tag ?
		keemash_fabric_v2_OtaPhase_OTA_PHASE_ABORTED :
		keemash_fabric_v2_OtaPhase_OTA_PHASE_TRANSFERRING;
	(void)send_status(transfer, phase, ESP_OK,
		phase == keemash_fabric_v2_OtaPhase_OTA_PHASE_ABORTED ?
		"aborted" : "accepted");
}

static void ota_v3_worker(void *context)
{
	(void)context;
	ota_v3_work_item_t item;
	TickType_t last_transfer_tick = xTaskGetTickCount();
	for (;;) {
		if (xQueueReceive(s_queue, &item,
			pdMS_TO_TICKS(OTA_V3_REPORT_PERIOD_MS)) != pdTRUE) {
			if ((TickType_t)(xTaskGetTickCount() - last_transfer_tick) >=
			    pdMS_TO_TICKS(OTA_V3_IDLE_TIMEOUT_MS) &&
			    xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE) {
				keemash_ota_v3_flash_status_t status = {0};
				keemash_ota_v3_flash_receiver_status(s_receiver, &status);
				if (status.active || status.verified) {
					esp_err_t err =
						keemash_ota_v3_flash_receiver_abort_current(s_receiver);
					ESP_LOGW(TAG, "idle transfer aborted: %s",
						esp_err_to_name(err));
				}
				xSemaphoreGive(s_lock);
			}
			(void)send_pending_boot_report();
			continue;
		}
		keemash_fabric_v2_OtaMeshMessage *message =
			calloc(1U, sizeof(*message));
		if (!message) continue;
		if (keemash_ota_v3_decode_mesh_message(item.bytes, item.length,
			message) == ESP_OK &&
		    xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE) {
			process_message(message);
			if (message->which_body ==
			    keemash_fabric_v2_OtaMeshMessage_transfer_tag)
				last_transfer_tick = xTaskGetTickCount();
			xSemaphoreGive(s_lock);
		}
		free(message);
	}
}
#endif

esp_err_t keemash_mesh_ota_v3_receiver_start(
	const keemash_mesh_ota_v3_config_t *config)
{
#if CONFIG_KEEMASH_OTA_V3_ENABLE
	if (!config || !config->preflight) return ESP_ERR_INVALID_ARG;
	if (s_worker) return ESP_OK;
	s_config = *config;
	s_lock = xSemaphoreCreateMutex();
	if (!s_lock) return ESP_ERR_NO_MEM;
	esp_err_t err = keemash_ota_v3_flash_receiver_create(&s_receiver);
	if (err != ESP_OK) {
		vSemaphoreDelete(s_lock);
		s_lock = NULL;
		return err;
	}
	s_queue = xQueueCreate(OTA_V3_QUEUE_LEN, sizeof(ota_v3_work_item_t));
	if (!s_queue) {
		keemash_ota_v3_flash_receiver_destroy(s_receiver);
		s_receiver = NULL;
		vSemaphoreDelete(s_lock);
		s_lock = NULL;
		return ESP_ERR_NO_MEM;
	}
	if (xTaskCreate(ota_v3_worker, "ota_v3_rx", OTA_V3_WORKER_STACK,
		NULL, OTA_V3_WORKER_PRIO, &s_worker) != pdPASS) {
		s_worker = NULL;
		vQueueDelete(s_queue);
		s_queue = NULL;
		keemash_ota_v3_flash_receiver_destroy(s_receiver);
		s_receiver = NULL;
		vSemaphoreDelete(s_lock);
		s_lock = NULL;
		return ESP_ERR_NO_MEM;
	}
	return ESP_OK;
#else
	(void)config;
	return ESP_ERR_NOT_SUPPORTED;
#endif
}

esp_err_t keemash_mesh_ota_v3_receiver_handle(
	const void *payload, size_t payload_len)
{
#if CONFIG_KEEMASH_OTA_V3_ENABLE
	if (!payload || payload_len == 0U ||
	    payload_len > keemash_fabric_v2_OtaMeshMessage_size)
		return ESP_ERR_INVALID_SIZE;
	if (!s_queue || !s_worker) return ESP_ERR_INVALID_STATE;
	ota_v3_work_item_t item = {.length = (uint16_t)payload_len};
	memcpy(item.bytes, payload, payload_len);
	return xQueueSend(s_queue, &item, pdMS_TO_TICKS(100)) == pdTRUE ?
		ESP_OK : ESP_ERR_TIMEOUT;
#else
	(void)payload;
	(void)payload_len;
	return ESP_ERR_NOT_SUPPORTED;
#endif
}

bool keemash_mesh_ota_v3_receiver_active(void)
{
#if CONFIG_KEEMASH_OTA_V3_ENABLE
	if (!s_receiver || !s_lock) return false;
	if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(20)) != pdTRUE) return true;
	keemash_ota_v3_flash_status_t status = {0};
	keemash_ota_v3_flash_receiver_status(s_receiver, &status);
	xSemaphoreGive(s_lock);
	return status.active || status.verified;
#else
	return false;
#endif
}
