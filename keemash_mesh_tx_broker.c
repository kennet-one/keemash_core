// SPDX-License-Identifier: GPL-2.0-only
#include "keemash_mesh_tx_broker.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "keemash_mesh_core.h"

typedef struct {
	bool used;
	bool sending;
	uint8_t priority;
	uint8_t dst[6];
	uint32_t ticket;
	size_t len;
	uint8_t *bytes;
} broker_slot_t;

struct keemash_mesh_tx_broker {
	keemash_mesh_tx_broker_config_t cfg;
	SemaphoreHandle_t lock;
	TaskHandle_t task;
	broker_slot_t *slots;
	uint8_t *storage;
	uint32_t next_ticket;
	bool stopping;
	keemash_mesh_tx_broker_stats_t stats;
};

static broker_slot_t *pick_next_locked(keemash_mesh_tx_broker_t *broker)
{
	broker_slot_t *best = NULL;
	for (uint16_t i = 0; i < broker->cfg.slots; i++) {
		broker_slot_t *slot = &broker->slots[i];
		if (!slot->used || slot->sending) continue;
		if (!best || slot->priority > best->priority ||
		    (slot->priority == best->priority &&
		     (int32_t)(slot->ticket - best->ticket) < 0)) best = slot;
	}
	if (best) best->sending = true;
	return best;
}

static void broker_task(void *arg)
{
	keemash_mesh_tx_broker_t *broker = arg;
	for (;;) {
		(void)ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(1000));
		for (;;) {
			if (xSemaphoreTake(broker->lock, portMAX_DELAY) != pdTRUE) continue;
			bool stopping = broker->stopping;
			broker_slot_t *slot = stopping ? NULL : pick_next_locked(broker);
			xSemaphoreGive(broker->lock);
			if (stopping) {
				broker->task = NULL;
				vTaskDelete(NULL);
			}
			if (!slot) break;
			esp_err_t err = broker->cfg.raw_send(broker->cfg.user, slot->dst,
							 slot->bytes, slot->len);
			if (xSemaphoreTake(broker->lock, portMAX_DELAY) == pdTRUE) {
				broker->stats.completed++;
				broker->stats.pending--;
				broker->stats.last_transport_err = err;
				if (err != ESP_OK) broker->stats.transport_errors++;
				uint8_t *bytes = slot->bytes;
				memset(slot, 0, sizeof(*slot));
				slot->bytes = bytes;
				xSemaphoreGive(broker->lock);
			}
		}
	}
}

esp_err_t keemash_mesh_tx_broker_init(keemash_mesh_tx_broker_t **out,
					       const keemash_mesh_tx_broker_config_t *config)
{
	if (!out || !config || !config->raw_send || config->slots == 0 ||
	    config->max_packet_size == 0) return ESP_ERR_INVALID_ARG;
	keemash_mesh_tx_broker_t *broker = calloc(1, sizeof(*broker));
	if (!broker) return ESP_ERR_NO_MEM;
	broker->cfg = *config;
	broker->lock = xSemaphoreCreateMutex();
	broker->slots = calloc(config->slots, sizeof(*broker->slots));
	broker->storage = calloc(config->slots, config->max_packet_size);
	if (!broker->lock || !broker->slots || !broker->storage) {
		keemash_mesh_tx_broker_deinit(broker);
		return ESP_ERR_NO_MEM;
	}
	for (uint16_t i = 0; i < config->slots; i++) {
		broker->slots[i].bytes = broker->storage +
						 (size_t)i * config->max_packet_size;
	}
	const char *name = config->task_name ? config->task_name : "mesh_tx";
	uint32_t stack = config->task_stack_words ? config->task_stack_words : 4096;
	UBaseType_t priority = config->task_priority ? config->task_priority : 6;
	if (xTaskCreate(broker_task, name, stack, broker, priority, &broker->task) != pdPASS) {
		keemash_mesh_tx_broker_deinit(broker);
		return ESP_ERR_NO_MEM;
	}
	*out = broker;
	return ESP_OK;
}

void keemash_mesh_tx_broker_deinit(keemash_mesh_tx_broker_t *broker)
{
	if (!broker) return;
	if (broker->lock && xSemaphoreTake(broker->lock, pdMS_TO_TICKS(100)) == pdTRUE) {
		broker->stopping = true;
		xSemaphoreGive(broker->lock);
	}
	if (broker->task) xTaskNotifyGive(broker->task);
	for (uint32_t i = 0; broker->task && i < 100; i++) vTaskDelay(pdMS_TO_TICKS(10));
	if (broker->task) return;
	if (broker->lock) vSemaphoreDelete(broker->lock);
	free(broker->storage);
	free(broker->slots);
	free(broker);
}

esp_err_t keemash_mesh_tx_broker_submit(keemash_mesh_tx_broker_t *broker,
						const uint8_t dst[6],
						const void *packet,
						size_t packet_len,
						uint8_t priority)
{
	if (!broker || !packet || packet_len == 0) return ESP_ERR_INVALID_ARG;
	if (packet_len > broker->cfg.max_packet_size) {
		if (xSemaphoreTake(broker->lock, pdMS_TO_TICKS(100)) == pdTRUE) {
			broker->stats.rejected_size++;
			xSemaphoreGive(broker->lock);
		}
		return ESP_ERR_INVALID_SIZE;
	}
	if (xSemaphoreTake(broker->lock, pdMS_TO_TICKS(100)) != pdTRUE) return ESP_ERR_TIMEOUT;
	broker_slot_t *slot = NULL;
	for (uint16_t i = 0; i < broker->cfg.slots; i++) {
		if (!broker->slots[i].used) { slot = &broker->slots[i]; break; }
	}
	if (!slot) {
		broker->stats.rejected_full++;
		xSemaphoreGive(broker->lock);
		return ESP_ERR_NO_MEM;
	}
	uint8_t *bytes = slot->bytes;
	memset(slot, 0, sizeof(*slot));
	slot->bytes = bytes;
	slot->used = true;
	slot->priority = priority;
	slot->ticket = ++broker->next_ticket;
	if (dst) memcpy(slot->dst, dst, sizeof(slot->dst));
	memcpy(slot->bytes, packet, packet_len);
	slot->len = packet_len;
	broker->stats.accepted++;
	broker->stats.pending++;
	TaskHandle_t task = broker->task;
	xSemaphoreGive(broker->lock);
	if (task) xTaskNotifyGive(task);
	return ESP_OK;
}

uint8_t keemash_mesh_packet_priority(const void *packet, size_t packet_len)
{
	if (!packet || packet_len < sizeof(mesh_v2_hdr_t)) {
		return KEEMASH_REL_PRIORITY_NORMAL;
	}
	const mesh_v2_hdr_t *header = packet;
	if (header->magic != MESH_PKT_MAGIC || header->version != MESH_PKT_VERSION_V2) {
		return KEEMASH_REL_PRIORITY_NORMAL;
	}
	if (header->type != MESH_V2_TYPE_RELIABLE_DATA ||
	    header->payload_len < sizeof(mesh_v2_reliable_hdr_t) ||
	    packet_len < sizeof(*header) + sizeof(mesh_v2_reliable_hdr_t)) {
		return KEEMASH_REL_PRIORITY_CONTROL;
	}
	const mesh_v2_reliable_hdr_t *reliable =
		(const mesh_v2_reliable_hdr_t *)((const uint8_t *)packet + sizeof(*header));
	return reliable->priority;
}

esp_err_t keemash_mesh_tx_broker_submit_auto(keemash_mesh_tx_broker_t *broker,
						     const uint8_t dst[6],
						     const void *packet,
						     size_t packet_len)
{
	return keemash_mesh_tx_broker_submit(broker, dst, packet, packet_len,
	                                      keemash_mesh_packet_priority(packet, packet_len));
}

void keemash_mesh_tx_broker_stats(keemash_mesh_tx_broker_t *broker,
					  keemash_mesh_tx_broker_stats_t *out)
{
	if (!out) return;
	memset(out, 0, sizeof(*out));
	if (!broker || xSemaphoreTake(broker->lock, pdMS_TO_TICKS(100)) != pdTRUE) return;
	*out = broker->stats;
	xSemaphoreGive(broker->lock);
}
