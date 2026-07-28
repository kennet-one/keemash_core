// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct keemash_mesh_event_outbox keemash_mesh_event_outbox_t;

typedef esp_err_t (*keemash_mesh_event_send_fn)(void *user, const char *text);

typedef struct {
	uint16_t slots;
	uint16_t text_size;
	uint16_t retry_ms;
	uint16_t task_stack_words;
	uint8_t task_priority;
	const char *task_name;
	keemash_mesh_event_send_fn send;
	void *user;
} keemash_mesh_event_outbox_config_t;

typedef struct {
	uint32_t accepted;
	uint32_t delivered;
	uint32_t coalesced;
	uint32_t overflow;
	uint32_t send_errors;
	uint32_t pending;
	uint32_t high_watermark;
	int32_t last_send_err;
} keemash_mesh_event_outbox_stats_t;

esp_err_t keemash_mesh_event_outbox_init(
	keemash_mesh_event_outbox_t **out,
	const keemash_mesh_event_outbox_config_t *config);
void keemash_mesh_event_outbox_deinit(keemash_mesh_event_outbox_t *outbox);

// FIFO events preserve enqueue order. A non-empty replace_key replaces the
// newest pending event with the same key instead of adding another copy.
esp_err_t keemash_mesh_event_outbox_enqueue(
	keemash_mesh_event_outbox_t *outbox,
	const char *replace_key,
	const char *text);

// Enqueue a related FIFO group atomically. Either every item is accepted in
// order or none are added.
esp_err_t keemash_mesh_event_outbox_enqueue_group(
	keemash_mesh_event_outbox_t *outbox,
	const char *const *texts,
	size_t count);

void keemash_mesh_event_outbox_stats(
	keemash_mesh_event_outbox_t *outbox,
	keemash_mesh_event_outbox_stats_t *out);

#ifdef __cplusplus
}
#endif
