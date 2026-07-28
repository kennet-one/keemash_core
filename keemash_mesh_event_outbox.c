// SPDX-License-Identifier: Apache-2.0
#include "keemash_mesh_event_outbox.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#define EVENT_KEY_MAX 16

typedef struct {
	bool used;
	bool sending;
	uint32_t ticket;
	char key[EVENT_KEY_MAX];
	char *text;
} event_slot_t;

struct keemash_mesh_event_outbox {
	keemash_mesh_event_outbox_config_t cfg;
	SemaphoreHandle_t lock;
	TaskHandle_t task;
	event_slot_t *slots;
	char *storage;
	uint32_t next_ticket;
	bool stopping;
	keemash_mesh_event_outbox_stats_t stats;
};

static event_slot_t *oldest_locked(keemash_mesh_event_outbox_t *outbox)
{
	event_slot_t *best = NULL;
	for (uint16_t i = 0; i < outbox->cfg.slots; i++) {
		event_slot_t *slot = &outbox->slots[i];
		if (!slot->used || slot->sending) continue;
		if (!best || (int32_t)(slot->ticket - best->ticket) < 0) best = slot;
	}
	if (best) best->sending = true;
	return best;
}

static event_slot_t *free_locked(keemash_mesh_event_outbox_t *outbox)
{
	for (uint16_t i = 0; i < outbox->cfg.slots; i++) {
		if (!outbox->slots[i].used) return &outbox->slots[i];
	}
	return NULL;
}

static void update_high_watermark_locked(keemash_mesh_event_outbox_t *outbox)
{
	if (outbox->stats.pending > outbox->stats.high_watermark) {
		outbox->stats.high_watermark = outbox->stats.pending;
	}
}

static void event_worker(void *arg)
{
	keemash_mesh_event_outbox_t *outbox = arg;
	for (;;) {
		(void)ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(outbox->cfg.retry_ms));
		for (;;) {
			if (xSemaphoreTake(outbox->lock, portMAX_DELAY) != pdTRUE) continue;
			bool stopping = outbox->stopping;
			event_slot_t *slot = stopping ? NULL : oldest_locked(outbox);
			xSemaphoreGive(outbox->lock);
			if (stopping) {
				outbox->task = NULL;
				vTaskDelete(NULL);
			}
			if (!slot) break;

			esp_err_t err = outbox->cfg.send(outbox->cfg.user, slot->text);
			if (xSemaphoreTake(outbox->lock, portMAX_DELAY) != pdTRUE) continue;
			outbox->stats.last_send_err = err;
			if (err == ESP_OK) {
				char *text = slot->text;
				memset(slot, 0, sizeof(*slot));
				slot->text = text;
				outbox->stats.delivered++;
				outbox->stats.pending--;
			} else {
				slot->sending = false;
				outbox->stats.send_errors++;
			}
			xSemaphoreGive(outbox->lock);
			if (err != ESP_OK) {
				vTaskDelay(pdMS_TO_TICKS(outbox->cfg.retry_ms));
				break;
			}
		}
	}
}

esp_err_t keemash_mesh_event_outbox_init(
	keemash_mesh_event_outbox_t **out,
	const keemash_mesh_event_outbox_config_t *config)
{
	if (!out || !config || !config->send || config->slots == 0 ||
	    config->text_size < 2) return ESP_ERR_INVALID_ARG;

	keemash_mesh_event_outbox_t *outbox = calloc(1, sizeof(*outbox));
	if (!outbox) return ESP_ERR_NO_MEM;
	outbox->cfg = *config;
	if (outbox->cfg.retry_ms == 0) outbox->cfg.retry_ms = 250;
	outbox->lock = xSemaphoreCreateMutex();
	outbox->slots = calloc(config->slots, sizeof(*outbox->slots));
	outbox->storage = calloc(config->slots, config->text_size);
	if (!outbox->lock || !outbox->slots || !outbox->storage) {
		keemash_mesh_event_outbox_deinit(outbox);
		return ESP_ERR_NO_MEM;
	}
	for (uint16_t i = 0; i < config->slots; i++) {
		outbox->slots[i].text = outbox->storage + (size_t)i * config->text_size;
	}
	const char *name = config->task_name ? config->task_name : "mesh_events";
	uint32_t stack = config->task_stack_words ? config->task_stack_words : 3072;
	UBaseType_t priority = config->task_priority ? config->task_priority : 4;
	if (xTaskCreate(event_worker, name, stack, outbox, priority,
	                &outbox->task) != pdPASS) {
		keemash_mesh_event_outbox_deinit(outbox);
		return ESP_ERR_NO_MEM;
	}
	*out = outbox;
	return ESP_OK;
}

void keemash_mesh_event_outbox_deinit(keemash_mesh_event_outbox_t *outbox)
{
	if (!outbox) return;
	if (outbox->lock &&
	    xSemaphoreTake(outbox->lock, pdMS_TO_TICKS(100)) == pdTRUE) {
		outbox->stopping = true;
		xSemaphoreGive(outbox->lock);
	}
	if (outbox->task) xTaskNotifyGive(outbox->task);
	for (uint32_t i = 0; outbox->task && i < 100; i++) {
		vTaskDelay(pdMS_TO_TICKS(10));
	}
	if (outbox->task) return;
	if (outbox->lock) vSemaphoreDelete(outbox->lock);
	free(outbox->storage);
	free(outbox->slots);
	free(outbox);
}

esp_err_t keemash_mesh_event_outbox_enqueue(
	keemash_mesh_event_outbox_t *outbox,
	const char *replace_key,
	const char *text)
{
	if (!outbox || !text || !text[0]) return ESP_ERR_INVALID_ARG;
	if (strnlen(text, outbox->cfg.text_size) >= outbox->cfg.text_size) {
		return ESP_ERR_INVALID_SIZE;
	}
	if (xSemaphoreTake(outbox->lock, pdMS_TO_TICKS(100)) != pdTRUE) {
		return ESP_ERR_TIMEOUT;
	}

	if (replace_key && replace_key[0]) {
		for (uint16_t i = 0; i < outbox->cfg.slots; i++) {
			event_slot_t *slot = &outbox->slots[i];
			if (slot->used && !slot->sending &&
			    strncmp(slot->key, replace_key, sizeof(slot->key)) == 0) {
				snprintf(slot->text, outbox->cfg.text_size, "%s", text);
				slot->ticket = ++outbox->next_ticket;
				outbox->stats.coalesced++;
				xSemaphoreGive(outbox->lock);
				xTaskNotifyGive(outbox->task);
				return ESP_OK;
			}
		}
	}

	event_slot_t *slot = free_locked(outbox);
	if (!slot) {
		outbox->stats.overflow++;
		xSemaphoreGive(outbox->lock);
		return ESP_ERR_NO_MEM;
	}
	char *storage = slot->text;
	memset(slot, 0, sizeof(*slot));
	slot->text = storage;
	slot->used = true;
	slot->ticket = ++outbox->next_ticket;
	if (replace_key) snprintf(slot->key, sizeof(slot->key), "%s", replace_key);
	snprintf(slot->text, outbox->cfg.text_size, "%s", text);
	outbox->stats.accepted++;
	outbox->stats.pending++;
	update_high_watermark_locked(outbox);
	xSemaphoreGive(outbox->lock);
	xTaskNotifyGive(outbox->task);
	return ESP_OK;
}

esp_err_t keemash_mesh_event_outbox_enqueue_group(
	keemash_mesh_event_outbox_t *outbox,
	const char *const *texts,
	size_t count)
{
	if (!outbox || !texts || count == 0 || count > outbox->cfg.slots) {
		return ESP_ERR_INVALID_ARG;
	}
	for (size_t i = 0; i < count; i++) {
		if (!texts[i] || !texts[i][0] ||
		    strnlen(texts[i], outbox->cfg.text_size) >= outbox->cfg.text_size) {
			return ESP_ERR_INVALID_SIZE;
		}
	}
	if (xSemaphoreTake(outbox->lock, pdMS_TO_TICKS(100)) != pdTRUE) {
		return ESP_ERR_TIMEOUT;
	}
	size_t free_count = 0;
	for (uint16_t i = 0; i < outbox->cfg.slots; i++) {
		if (!outbox->slots[i].used) free_count++;
	}
	if (free_count < count) {
		outbox->stats.overflow++;
		xSemaphoreGive(outbox->lock);
		return ESP_ERR_NO_MEM;
	}
	for (size_t n = 0; n < count; n++) {
		event_slot_t *slot = free_locked(outbox);
		char *storage = slot->text;
		memset(slot, 0, sizeof(*slot));
		slot->text = storage;
		slot->used = true;
		slot->ticket = ++outbox->next_ticket;
		snprintf(slot->text, outbox->cfg.text_size, "%s", texts[n]);
		outbox->stats.accepted++;
		outbox->stats.pending++;
	}
	update_high_watermark_locked(outbox);
	xSemaphoreGive(outbox->lock);
	xTaskNotifyGive(outbox->task);
	return ESP_OK;
}

void keemash_mesh_event_outbox_stats(
	keemash_mesh_event_outbox_t *outbox,
	keemash_mesh_event_outbox_stats_t *out)
{
	if (!out) return;
	memset(out, 0, sizeof(*out));
	if (!outbox ||
	    xSemaphoreTake(outbox->lock, pdMS_TO_TICKS(100)) != pdTRUE) return;
	*out = outbox->stats;
	xSemaphoreGive(outbox->lock);
}
