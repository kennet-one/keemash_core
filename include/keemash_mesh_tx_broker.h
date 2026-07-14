// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct keemash_mesh_tx_broker keemash_mesh_tx_broker_t;

typedef esp_err_t (*keemash_mesh_tx_raw_send_fn)(void *user,
						 const uint8_t dst[6],
						 const void *packet,
						 size_t packet_len);

typedef struct {
	uint16_t slots;
	uint16_t max_packet_size;
	uint16_t task_stack_words;
	uint8_t task_priority;
	const char *task_name;
	keemash_mesh_tx_raw_send_fn raw_send;
	void *user;
} keemash_mesh_tx_broker_config_t;

typedef struct {
	uint32_t accepted;
	uint32_t completed;
	uint32_t rejected_full;
	uint32_t rejected_size;
	uint32_t transport_errors;
	uint32_t pending;
	int32_t last_transport_err;
} keemash_mesh_tx_broker_stats_t;

esp_err_t keemash_mesh_tx_broker_init(keemash_mesh_tx_broker_t **out,
					       const keemash_mesh_tx_broker_config_t *config);
void keemash_mesh_tx_broker_deinit(keemash_mesh_tx_broker_t *broker);

// ESP_OK means the broker owns a private copy and will make the physical send.
esp_err_t keemash_mesh_tx_broker_submit(keemash_mesh_tx_broker_t *broker,
						const uint8_t dst[6],
						const void *packet,
						size_t packet_len,
						uint8_t priority);

// Classify a KeeMASH packet from its reliable header. Non-reliable packets use
// NORMAL priority, while reliability control frames use CONTROL priority.
uint8_t keemash_mesh_packet_priority(const void *packet, size_t packet_len);

esp_err_t keemash_mesh_tx_broker_submit_auto(keemash_mesh_tx_broker_t *broker,
						     const uint8_t dst[6],
						     const void *packet,
						     size_t packet_len);

void keemash_mesh_tx_broker_stats(keemash_mesh_tx_broker_t *broker,
					  keemash_mesh_tx_broker_stats_t *out);

#ifdef __cplusplus
}
#endif
