// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"
#include "freertos/FreeRTOS.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KEEMASH_WEEKLY_SCHEDULE_MAX_POINTS 8U
#define KEEMASH_WEEKLY_SCHEDULE_ALL_DAYS 0x7fU
#define KEEMASH_WEEKLY_SCHEDULE_NO_INDEX 0xffU
#define KEEMASH_WEEKLY_SCHEDULE_APPLY_NONE 0U
#define KEEMASH_WEEKLY_SCHEDULE_APPLY_CATCH_UP 1U
#define KEEMASH_WEEKLY_SCHEDULE_APPLY_SCHEDULED 2U

typedef struct {
	bool enabled;
	uint16_t minute_of_day;
	uint8_t action;
	uint8_t days_mask;
} keemash_weekly_schedule_point_t;

typedef struct {
	uint32_t generation;
	bool enabled;
	bool persistence_enabled;
	uint8_t count;
	keemash_weekly_schedule_point_t points[KEEMASH_WEEKLY_SCHEDULE_MAX_POINTS];
} keemash_weekly_schedule_config_t;

typedef struct {
	keemash_weekly_schedule_config_t config;
	bool clock_valid;
	bool catch_up_pending;
	bool last_apply_valid;
	uint8_t local_weekday;
	uint16_t local_minute;
	uint8_t active_index;
	uint8_t next_index;
	uint16_t next_in_minutes;
	uint8_t last_apply_index;
	uint8_t last_apply_kind;
	uint32_t last_apply_age_ms;
	uint32_t time_sync_age_ms;
	esp_err_t last_error;
} keemash_weekly_schedule_status_t;

typedef esp_err_t (*keemash_weekly_schedule_apply_fn)(
	void *user, const keemash_weekly_schedule_point_t *point,
	uint8_t index, bool catch_up);

typedef struct {
	const char *nvs_namespace;
	const char *nvs_key;
	uint32_t blob_magic;
	uint8_t max_action;
	bool catch_up_on_clock_ready;
	uint32_t stage_timeout_ms;
	uint32_t task_period_ms;
	uint32_t task_stack_words;
	UBaseType_t task_priority;
	const char *task_name;
	keemash_weekly_schedule_apply_fn apply;
	void *user;
} keemash_weekly_schedule_options_t;

typedef struct keemash_weekly_schedule keemash_weekly_schedule_t;

esp_err_t keemash_weekly_schedule_start(
	keemash_weekly_schedule_t **out,
	const keemash_weekly_schedule_options_t *options);
void keemash_weekly_schedule_stop(keemash_weekly_schedule_t *schedule);

esp_err_t keemash_weekly_schedule_stage_begin(
	keemash_weekly_schedule_t *schedule, uint32_t generation,
	uint8_t count, bool enabled, bool persistence_enabled);
esp_err_t keemash_weekly_schedule_stage_point(
	keemash_weekly_schedule_t *schedule, uint32_t generation,
	uint8_t index, const keemash_weekly_schedule_point_t *point);
esp_err_t keemash_weekly_schedule_stage_commit(
	keemash_weekly_schedule_t *schedule, uint32_t generation);
void keemash_weekly_schedule_get_status(
	keemash_weekly_schedule_t *schedule,
	keemash_weekly_schedule_status_t *status);

bool keemash_weekly_schedule_self_test(void);

#ifdef __cplusplus
}
#endif
