// SPDX-License-Identifier: Apache-2.0
#include "keemash_mesh_time.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "esp_log.h"

#define KEEMASH_TIME_VALID_EPOCH 1577836800LL

typedef struct __attribute__((packed)) {
	uint8_t magic;
	uint8_t version;
	uint8_t type;
	uint8_t reserved;
	uint32_t counter;
	uint8_t src_mac[6];
	uint8_t payload[32];
} keemash_v1_packet_t;

typedef struct __attribute__((packed)) {
	int64_t epoch_sec;
	uint32_t seq;
} keemash_v1_time_payload_t;

static const char *TAG = "mesh_time";
static bool s_have_time;
static uint32_t s_last_generation;
static uint32_t s_last_source_uptime_s;

void keemash_mesh_time_init(const char *tz_rule)
{
	if (!tz_rule || !tz_rule[0]) return;
	setenv("TZ", tz_rule, 1);
	tzset();
}

static esp_err_t apply_time(int64_t epoch_sec, uint32_t generation, const char *profile)
{
	if (epoch_sec <= KEEMASH_TIME_VALID_EPOCH || generation == 0) {
		return ESP_ERR_INVALID_ARG;
	}
	if (s_have_time && generation <= s_last_generation) return ESP_OK;
	struct timeval tv = {
		.tv_sec = (time_t)epoch_sec,
		.tv_usec = 0,
	};
	if (settimeofday(&tv, NULL) != 0) return ESP_FAIL;
	s_have_time = true;
	s_last_generation = generation;
	ESP_LOGI(TAG, "TIME %s RX generation=%" PRIu32 " epoch=%" PRId64,
	         profile, generation, epoch_sec);
	return ESP_OK;
}

esp_err_t keemash_mesh_time_handle_v1(const void *packet, size_t packet_len)
{
	if (!packet || packet_len < sizeof(keemash_v1_packet_t)) {
		return ESP_ERR_INVALID_SIZE;
	}
	const keemash_v1_packet_t *p = packet;
	if (p->magic != MESH_PKT_MAGIC || p->version != MESH_PKT_VERSION ||
	    p->type != MESH_TIME_SYNC_TYPE_TIME) return ESP_ERR_INVALID_ARG;
	keemash_v1_time_payload_t time_payload = {0};
	memcpy(&time_payload, p->payload, sizeof(time_payload));
	return apply_time(time_payload.epoch_sec, time_payload.seq, "V1");
}

esp_err_t keemash_mesh_time_apply_v2(const mesh_v2_time_payload_t *time_sync)
{
	if (!time_sync) return ESP_ERR_INVALID_ARG;
	if (s_have_time && s_last_source_uptime_s != 0 && time_sync->source_uptime_s != 0 &&
	    time_sync->source_uptime_s + 5U < s_last_source_uptime_s) {
		// A lower root uptime identifies a new root boot generation. Its TIME
		// sequence is allowed to restart without waiting to catch the old value.
		s_have_time = false;
		s_last_generation = 0;
	}
	esp_err_t err = apply_time(time_sync->epoch_sec, time_sync->generation, "V2");
	if (err == ESP_OK) s_last_source_uptime_s = time_sync->source_uptime_s;
	return err;
}
