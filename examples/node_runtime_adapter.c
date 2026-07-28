// SPDX-License-Identifier: Apache-2.0
// Minimal transport/runtime adapter for a new ESP-IDF mesh node.

#include <stdbool.h>
#include <string.h>

#include "esp_mesh.h"
#include "esp_wifi.h"

#include "keemash_mesh_hooks.h"
#include "keemash_mesh_log_stream.h"
#include "keemash_mesh_node.h"
#include "keemash_mesh_tx_broker.h"

static keemash_mesh_tx_broker_t *s_broker;
static bool s_parent_connected;

static esp_err_t raw_send(void *user, const uint8_t dst[6],
                          const void *packet, size_t packet_len)
{
	(void)user;
	if (!s_parent_connected) return ESP_ERR_INVALID_STATE;
	mesh_addr_t destination = {0};
	if (dst) memcpy(destination.addr, dst, sizeof(destination.addr));
	mesh_data_t data = {
		.data = (uint8_t *)packet,
		.size = packet_len,
		.proto = MESH_PROTO_BIN,
		.tos = MESH_TOS_P2P,
	};
	return esp_mesh_send(&destination, &data, MESH_DATA_P2P, NULL, 0);
}

esp_err_t keemash_mesh_transport_send(const uint8_t dst[6],
                                      const void *packet, size_t packet_len)
{
	if (!s_broker) return ESP_ERR_INVALID_STATE;
	return keemash_mesh_tx_broker_submit_auto(s_broker, dst, packet, packet_len);
}

void keemash_mesh_get_local_mac(uint8_t mac[6])
{
	(void)esp_wifi_get_mac(WIFI_IF_STA, mac);
}

esp_err_t app_mesh_runtime_init(const char *tag, bool relay_eligible)
{
	keemash_mesh_tx_broker_config_t config = {
		.slots = 24,
		.control_reserved_slots = 4,
		.max_packet_size = 512,
		.task_stack_words = 4096,
		.task_priority = 7,
		.task_name = "mesh_tx",
		.raw_send = raw_send,
	};
	esp_err_t err = keemash_mesh_tx_broker_init(&s_broker, &config);
	if (err != ESP_OK) return err;
	mesh_v2_node_set_relay_eligible(relay_eligible);
	mesh_v2_node_init(tag);
	return keemash_mesh_log_stream_init(tag);
}

void app_mesh_runtime_parent_connected(void)
{
	s_parent_connected = true;
	keemash_mesh_log_stream_on_mesh_connected();
	mesh_v2_node_on_mesh_connected();
}

void app_mesh_runtime_parent_disconnected(void)
{
	s_parent_connected = false;
	mesh_v2_node_on_mesh_disconnected();
	keemash_mesh_log_stream_on_mesh_disconnected();
}
