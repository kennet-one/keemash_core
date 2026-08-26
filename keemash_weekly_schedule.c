// SPDX-License-Identifier: Apache-2.0
#include "keemash_weekly_schedule.h"
#include "keemash_mesh_time.h"

#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "nvs.h"

#define SCHEDULE_BLOB_VERSION 1U
#define SCHEDULE_VALID_EPOCH 1577836800LL
#define SCHEDULE_FLAG_ENABLED 0x01U
#define SCHEDULE_FLAG_PERSIST 0x02U
#define POINT_FLAG_ENABLED 0x80U
#define DEFAULT_STAGE_TIMEOUT_MS 30000U
#define DEFAULT_TASK_PERIOD_MS 1000U
#define DEFAULT_TASK_STACK_WORDS 3584U
#define DEFAULT_TASK_PRIORITY 7U
#define CLOCK_CONTINUITY_LIMIT_SEC 120U
#define CLOCK_DRIFT_LIMIT_SEC 5U
#define APPLY_RETRY_MS 5000U

typedef struct __attribute__((packed)) {
	uint16_t minute_of_day;
	uint8_t days_mask;
	uint8_t action_flags;
} persisted_point_t;

typedef struct __attribute__((packed)) {
	uint32_t magic;
	uint8_t version;
	uint8_t count;
	uint8_t flags;
	uint8_t reserved;
	uint32_t generation;
	persisted_point_t points[KEEMASH_WEEKLY_SCHEDULE_MAX_POINTS];
	uint32_t checksum;
} schedule_blob_t;

typedef struct {
	bool active;
	uint32_t started_ms;
	uint8_t received_mask;
	keemash_weekly_schedule_config_t config;
} schedule_stage_t;

struct keemash_weekly_schedule {
	SemaphoreHandle_t lock;
	TaskHandle_t task;
	char nvs_namespace[16];
	char nvs_key[16];
	char task_name[16];
	uint32_t blob_magic;
	uint8_t max_action;
	bool catch_up_on_clock_ready;
	uint32_t stage_timeout_ms;
	uint32_t task_period_ms;
	uint32_t task_stack_words;
	UBaseType_t task_priority;
	keemash_weekly_schedule_apply_fn apply;
	void *user;
	keemash_weekly_schedule_config_t config;
	schedule_stage_t stage;
	uint32_t last_run_day[KEEMASH_WEEKLY_SCHEDULE_MAX_POINTS];
	bool catch_up_pending;
	bool last_clock_valid;
	time_t last_wall_epoch;
	uint32_t last_sample_ms;
	bool retry_pending;
	uint32_t retry_generation;
	uint32_t retry_day_key;
	uint32_t next_retry_ms;
	uint8_t retry_index;
	bool last_apply_valid;
	uint8_t last_apply_index;
	uint8_t last_apply_kind;
	uint32_t last_apply_ms;
	esp_err_t last_error;
};

static const char *TAG = "weekly_schedule";

static uint32_t monotonic_ms(void)
{
	return (uint32_t)((uint64_t)esp_timer_get_time() / 1000ULL);
}

static uint32_t checksum32(const void *data, size_t length)
{
	const uint8_t *bytes = data;
	uint32_t value = 2166136261UL;
	for (size_t i = 0; i < length; i++) {
		value ^= bytes[i];
		value *= 16777619UL;
	}
	return value;
}

static bool point_valid(const keemash_weekly_schedule_t *schedule,
			const keemash_weekly_schedule_point_t *point)
{
	return schedule && point && point->minute_of_day < 24U * 60U &&
	       point->days_mask != 0 &&
	       (point->days_mask & ~KEEMASH_WEEKLY_SCHEDULE_ALL_DAYS) == 0 &&
	       point->action <= schedule->max_action;
}

static bool config_valid(const keemash_weekly_schedule_t *schedule,
			 const keemash_weekly_schedule_config_t *config)
{
	if (!schedule || !config || config->generation == 0 ||
	    config->count > KEEMASH_WEEKLY_SCHEDULE_MAX_POINTS) return false;
	for (uint8_t i = 0; i < config->count; i++) {
		if (!point_valid(schedule, &config->points[i])) return false;
		if (!config->points[i].enabled) continue;
		for (uint8_t j = 0; j < i; j++) {
			if (config->points[j].enabled &&
			    config->points[j].minute_of_day == config->points[i].minute_of_day &&
			    (config->points[j].days_mask & config->points[i].days_mask) != 0) {
				return false;
			}
		}
	}
	return true;
}

static uint8_t weekday_index(const struct tm *local)
{
	return (uint8_t)((local->tm_wday + 6) % 7);
}

static bool point_applies_on(const keemash_weekly_schedule_point_t *point,
			     int weekday)
{
	return point->enabled && weekday >= 0 && weekday < 7 &&
	       (point->days_mask & (1U << weekday)) != 0;
}

static uint8_t latest_point_index(const keemash_weekly_schedule_config_t *config,
				  int weekday, uint16_t minute)
{
	uint32_t best_age = UINT_MAX;
	uint8_t best = KEEMASH_WEEKLY_SCHEDULE_NO_INDEX;
	for (uint8_t day_back = 0; day_back < 7; day_back++) {
		int day = (weekday - day_back + 7) % 7;
		for (uint8_t i = 0; i < config->count; i++) {
			const keemash_weekly_schedule_point_t *point = &config->points[i];
			if (!point_applies_on(point, day)) continue;
			if (day_back == 0 && point->minute_of_day > minute) continue;
			uint32_t age = (uint32_t)day_back * 1440U + minute -
				       point->minute_of_day;
			if (age < best_age) {
				best_age = age;
				best = i;
			}
		}
	}
	return best;
}

static uint8_t next_point_index(const keemash_weekly_schedule_config_t *config,
				int weekday, uint16_t minute,
				uint16_t *distance)
{
	uint32_t best_distance = UINT_MAX;
	uint8_t best = KEEMASH_WEEKLY_SCHEDULE_NO_INDEX;
	for (uint8_t day_forward = 0; day_forward < 7; day_forward++) {
		int day = (weekday + day_forward) % 7;
		for (uint8_t i = 0; i < config->count; i++) {
			const keemash_weekly_schedule_point_t *point = &config->points[i];
			if (!point_applies_on(point, day)) continue;
			int32_t delta = (int32_t)day_forward * 1440 +
					(int32_t)point->minute_of_day - minute;
			if (delta <= 0) delta += 7 * 1440;
			if ((uint32_t)delta < best_distance) {
				best_distance = (uint32_t)delta;
				best = i;
			}
		}
	}
	if (distance) {
		*distance = best_distance == UINT_MAX ? UINT16_MAX :
			(uint16_t)(best_distance > UINT16_MAX ? UINT16_MAX : best_distance);
	}
	return best;
}

static uint32_t local_day_key(const struct tm *local)
{
	return ((uint32_t)(local->tm_year + 1900) << 9) |
	       (uint32_t)local->tm_yday;
}

static bool clock_snapshot(struct tm *local, time_t *epoch)
{
	time_t now = time(NULL);
	if (now <= (time_t)SCHEDULE_VALID_EPOCH || localtime_r(&now, local) == NULL) {
		return false;
	}
	if (epoch) *epoch = now;
	return true;
}

static schedule_blob_t config_to_blob(
	const keemash_weekly_schedule_t *schedule,
	const keemash_weekly_schedule_config_t *config)
{
	schedule_blob_t blob = {
		.magic = schedule->blob_magic,
		.version = SCHEDULE_BLOB_VERSION,
		.count = config->count,
		.flags = (config->enabled ? SCHEDULE_FLAG_ENABLED : 0U) |
			 (config->persistence_enabled ? SCHEDULE_FLAG_PERSIST : 0U),
		.generation = config->generation,
	};
	for (uint8_t i = 0; i < config->count; i++) {
		blob.points[i].minute_of_day = config->points[i].minute_of_day;
		blob.points[i].days_mask = config->points[i].days_mask;
		blob.points[i].action_flags = config->points[i].action |
			(config->points[i].enabled ? POINT_FLAG_ENABLED : 0U);
	}
	blob.checksum = checksum32(&blob, offsetof(schedule_blob_t, checksum));
	return blob;
}

static keemash_weekly_schedule_config_t blob_to_config(
	const schedule_blob_t *blob)
{
	keemash_weekly_schedule_config_t config = {
		.generation = blob->generation,
		.enabled = (blob->flags & SCHEDULE_FLAG_ENABLED) != 0,
		.persistence_enabled = (blob->flags & SCHEDULE_FLAG_PERSIST) != 0,
		.count = blob->count,
	};
	for (uint8_t i = 0; i < config.count &&
		     i < KEEMASH_WEEKLY_SCHEDULE_MAX_POINTS; i++) {
		config.points[i].minute_of_day = blob->points[i].minute_of_day;
		config.points[i].days_mask = blob->points[i].days_mask;
		config.points[i].enabled =
			(blob->points[i].action_flags & POINT_FLAG_ENABLED) != 0;
		config.points[i].action =
			blob->points[i].action_flags & ~POINT_FLAG_ENABLED;
	}
	return config;
}

static esp_err_t persist_config(keemash_weekly_schedule_t *schedule,
				const keemash_weekly_schedule_config_t *config)
{
	nvs_handle_t handle;
	esp_err_t err = nvs_open(schedule->nvs_namespace, NVS_READWRITE, &handle);
	if (err != ESP_OK) return err;
	if (config->persistence_enabled) {
		schedule_blob_t blob = config_to_blob(schedule, config);
		err = nvs_set_blob(handle, schedule->nvs_key, &blob, sizeof(blob));
	} else {
		err = nvs_erase_key(handle, schedule->nvs_key);
		if (err == ESP_ERR_NVS_NOT_FOUND) err = ESP_OK;
	}
	if (err == ESP_OK) err = nvs_commit(handle);
	nvs_close(handle);
	return err;
}

static void load_config(keemash_weekly_schedule_t *schedule)
{
	memset(&schedule->config, 0, sizeof(schedule->config));
	schedule->config.generation = 1;
	nvs_handle_t handle;
	if (nvs_open(schedule->nvs_namespace, NVS_READONLY, &handle) != ESP_OK) return;
	schedule_blob_t blob = {0};
	size_t size = sizeof(blob);
	esp_err_t err = nvs_get_blob(handle, schedule->nvs_key, &blob, &size);
	nvs_close(handle);
	if (err != ESP_OK || size != sizeof(blob) ||
	    blob.magic != schedule->blob_magic ||
	    blob.version != SCHEDULE_BLOB_VERSION ||
	    blob.checksum != checksum32(&blob, offsetof(schedule_blob_t, checksum))) {
		if (err != ESP_ERR_NVS_NOT_FOUND) ESP_LOGW(TAG, "stored schedule rejected");
		return;
	}
	keemash_weekly_schedule_config_t candidate = blob_to_config(&blob);
	if (!candidate.persistence_enabled || !config_valid(schedule, &candidate)) {
		ESP_LOGW(TAG, "stored schedule validation failed");
		return;
	}
	schedule->config = candidate;
}

static void expire_stage_locked(keemash_weekly_schedule_t *schedule,
				uint32_t now)
{
	if (schedule->stage.active &&
	    now - schedule->stage.started_ms >= schedule->stage_timeout_ms) {
		memset(&schedule->stage, 0, sizeof(schedule->stage));
		ESP_LOGW(TAG, "staged schedule expired");
	}
}

static bool deadline_reached(uint32_t now, uint32_t deadline)
{
	return (int32_t)(now - deadline) >= 0;
}

static bool clock_is_continuous(time_t previous_epoch, time_t current_epoch,
				uint32_t previous_ms, uint32_t current_ms)
{
	int64_t wall_delta = (int64_t)current_epoch - (int64_t)previous_epoch;
	uint32_t monotonic_delta_ms = current_ms - previous_ms;
	int64_t monotonic_delta = (int64_t)((monotonic_delta_ms + 500U) / 1000U);
	int64_t drift = wall_delta - monotonic_delta;
	if (drift < 0) drift = -drift;
	return wall_delta >= 0 && wall_delta <= CLOCK_CONTINUITY_LIMIT_SEC &&
	       drift <= CLOCK_DRIFT_LIMIT_SEC;
}

static void record_apply_result(keemash_weekly_schedule_t *schedule,
				const keemash_weekly_schedule_config_t *config,
				uint8_t index, bool catch_up, uint32_t day_key,
				esp_err_t error, uint32_t now)
{
	if (xSemaphoreTake(schedule->lock, portMAX_DELAY) != pdTRUE) return;
	if (schedule->config.generation != config->generation) {
		xSemaphoreGive(schedule->lock);
		return;
	}
	schedule->last_error = error;
	if (error == ESP_OK) {
		schedule->last_apply_valid = true;
		schedule->last_apply_index = index;
		schedule->last_apply_kind = catch_up ?
			KEEMASH_WEEKLY_SCHEDULE_APPLY_CATCH_UP :
			KEEMASH_WEEKLY_SCHEDULE_APPLY_SCHEDULED;
		schedule->last_apply_ms = now;
		schedule->next_retry_ms = 0;
		if (catch_up) {
			schedule->catch_up_pending = false;
		} else {
			schedule->last_run_day[index] = day_key;
			schedule->retry_pending = false;
		}
	} else {
		schedule->next_retry_ms = now + APPLY_RETRY_MS;
		if (!catch_up) {
			schedule->retry_pending = true;
			schedule->retry_generation = config->generation;
			schedule->retry_index = index;
			schedule->retry_day_key = day_key;
		}
	}
	xSemaphoreGive(schedule->lock);
}

static esp_err_t apply_point(keemash_weekly_schedule_t *schedule,
			     const keemash_weekly_schedule_config_t *config,
			     uint8_t index, bool catch_up, uint32_t day_key,
			     uint32_t now)
{
	esp_err_t err = schedule->apply(schedule->user, &config->points[index],
					index, catch_up);
	record_apply_result(schedule, config, index, catch_up, day_key, err, now);
	if (err != ESP_OK) {
		ESP_LOGE(TAG, "%s point %u failed: %s",
			 catch_up ? "catch-up" : "scheduled", (unsigned)index,
			 esp_err_to_name(err));
	}
	return err;
}

static void run_scheduled_point(keemash_weekly_schedule_t *schedule,
				const keemash_weekly_schedule_config_t *config,
				uint8_t index, uint32_t day_key, uint32_t now)
{
	bool execute = false;
	if (xSemaphoreTake(schedule->lock, portMAX_DELAY) == pdTRUE) {
		bool retry_wait = schedule->retry_pending &&
			schedule->retry_generation == config->generation &&
			schedule->retry_index == index &&
			schedule->retry_day_key == day_key &&
			!deadline_reached(now, schedule->next_retry_ms);
		execute = schedule->config.generation == config->generation &&
			schedule->last_run_day[index] != day_key && !retry_wait;
		xSemaphoreGive(schedule->lock);
	}
	if (!execute) return;
	if (apply_point(schedule, config, index, false, day_key, now) == ESP_OK) {
		ESP_LOGI(TAG, "point %u applied action=%u", (unsigned)index,
			 (unsigned)config->points[index].action);
	}
}

static void run_points_for_minute(keemash_weekly_schedule_t *schedule,
				  const keemash_weekly_schedule_config_t *config,
				  const struct tm *local, uint32_t now)
{
	uint8_t weekday = weekday_index(local);
	uint16_t minute = (uint16_t)(local->tm_hour * 60 + local->tm_min);
	uint32_t day_key = local_day_key(local);
	for (uint8_t i = 0; i < config->count; i++) {
		const keemash_weekly_schedule_point_t *point = &config->points[i];
		if (point_applies_on(point, weekday) && point->minute_of_day == minute) {
			run_scheduled_point(schedule, config, i, day_key, now);
		}
	}
}

static void run_pending_retry(keemash_weekly_schedule_t *schedule,
			      const keemash_weekly_schedule_config_t *config,
			      uint32_t now)
{
	bool execute = false;
	uint8_t index = KEEMASH_WEEKLY_SCHEDULE_NO_INDEX;
	uint32_t day_key = 0;
	if (xSemaphoreTake(schedule->lock, portMAX_DELAY) == pdTRUE) {
		if (schedule->retry_pending &&
		    schedule->retry_generation == config->generation &&
		    schedule->retry_index < config->count &&
		    deadline_reached(now, schedule->next_retry_ms)) {
			execute = true;
			index = schedule->retry_index;
			day_key = schedule->retry_day_key;
		}
		xSemaphoreGive(schedule->lock);
	}
	if (execute) {
		(void)apply_point(schedule, config, index, false, day_key, now);
	}
}

static void schedule_task(void *arg)
{
	keemash_weekly_schedule_t *schedule = arg;
	for (;;) {
		vTaskDelay(pdMS_TO_TICKS(schedule->task_period_ms));
		struct tm local = {0};
		time_t epoch = 0;
		uint32_t now = monotonic_ms();
		bool clock_valid = clock_snapshot(&local, &epoch);
		keemash_weekly_schedule_config_t config;
		bool catch_up = false, continuous = false;
		time_t previous_epoch = 0;
		if (xSemaphoreTake(schedule->lock, portMAX_DELAY) != pdTRUE) continue;
		expire_stage_locked(schedule, now);
		config = schedule->config;
		if (!clock_valid) {
			schedule->last_clock_valid = false;
		} else {
			previous_epoch = schedule->last_wall_epoch;
			continuous = schedule->last_clock_valid &&
				clock_is_continuous(schedule->last_wall_epoch, epoch,
						    schedule->last_sample_ms, now);
			if (!schedule->last_clock_valid || !continuous) {
				schedule->catch_up_pending = config.enabled;
				schedule->retry_pending = false;
				schedule->next_retry_ms = 0;
			}
			schedule->last_clock_valid = true;
			schedule->last_wall_epoch = epoch;
			schedule->last_sample_ms = now;
		}
		catch_up = schedule->catch_up_pending && config.enabled && clock_valid &&
			(schedule->next_retry_ms == 0 ||
			 deadline_reached(now, schedule->next_retry_ms));
		if (catch_up && !schedule->catch_up_on_clock_ready) {
			schedule->catch_up_pending = false;
		}
		xSemaphoreGive(schedule->lock);
		if (!clock_valid || !config.enabled) continue;

		uint8_t weekday = weekday_index(&local);
		uint16_t minute = (uint16_t)(local.tm_hour * 60 + local.tm_min);
		if (catch_up && schedule->catch_up_on_clock_ready) {
			uint8_t latest = latest_point_index(&config, weekday, minute);
			if (latest != KEEMASH_WEEKLY_SCHEDULE_NO_INDEX) {
				esp_err_t err = apply_point(schedule, &config, latest, true,
							local_day_key(&local), now);
				if (err == ESP_OK && config.points[latest].minute_of_day == minute &&
				    xSemaphoreTake(schedule->lock, portMAX_DELAY) == pdTRUE) {
					if (schedule->config.generation == config.generation) {
						schedule->last_run_day[latest] = local_day_key(&local);
					}
					xSemaphoreGive(schedule->lock);
				}
			} else if (xSemaphoreTake(schedule->lock, portMAX_DELAY) == pdTRUE) {
				if (schedule->config.generation == config.generation) {
					schedule->catch_up_pending = false;
					schedule->next_retry_ms = 0;
				}
				xSemaphoreGive(schedule->lock);
			}
		}
		run_pending_retry(schedule, &config, now);

		if (continuous && previous_epoch < epoch) {
			time_t boundary = ((previous_epoch / 60) + 1) * 60;
			for (; boundary <= epoch; boundary += 60) {
				struct tm crossed = {0};
				if (localtime_r(&boundary, &crossed) != NULL) {
					run_points_for_minute(schedule, &config, &crossed, now);
				}
			}
		}
		// This also retries a failed point while its minute is still current.
		run_points_for_minute(schedule, &config, &local, now);
	}
}

bool keemash_weekly_schedule_self_test(void)
{
	keemash_weekly_schedule_t schedule = {.max_action = 1};
	keemash_weekly_schedule_config_t config = {
		.generation = 7,
		.enabled = true,
		.count = 2,
		.points = {
			{true, 360, 1, KEEMASH_WEEKLY_SCHEDULE_ALL_DAYS},
			{true, 1380, 0, KEEMASH_WEEKLY_SCHEDULE_ALL_DAYS},
		},
	};
	if (!config_valid(&schedule, &config) ||
	    latest_point_index(&config, 0, 400) != 0 ||
	    latest_point_index(&config, 0, 100) != 1) return false;
	uint16_t distance = 0;
	if (next_point_index(&config, 0, 400, &distance) != 1 ||
	    distance != 980) return false;
	config.points[1].minute_of_day = config.points[0].minute_of_day;
	if (config_valid(&schedule, &config)) return false;
	config.points[1].days_mask = 1U << 1;
	config.points[0].days_mask = 1U << 0;
	if (!config_valid(&schedule, &config)) return false;
	config.points[0].action = 2;
	if (config_valid(&schedule, &config)) return false;
	if (!clock_is_continuous(1000, 1061, 1000, 62000) ||
	    clock_is_continuous(1000, 1121, 1000, 122000) ||
	    clock_is_continuous(1000, 995, 1000, 6000) ||
	    clock_is_continuous(1000, 1070, 1000, 62000)) return false;
	return true;
}

esp_err_t keemash_weekly_schedule_start(
	keemash_weekly_schedule_t **out,
	const keemash_weekly_schedule_options_t *options)
{
	if (!out || *out || !options || !options->nvs_namespace ||
	    !options->nvs_key || !options->blob_magic || !options->apply ||
	    strlen(options->nvs_namespace) >= 16 || strlen(options->nvs_key) >= 16) {
		return ESP_ERR_INVALID_ARG;
	}
	if (!keemash_weekly_schedule_self_test()) return ESP_FAIL;
	keemash_weekly_schedule_t *schedule = calloc(1, sizeof(*schedule));
	if (!schedule) return ESP_ERR_NO_MEM;
	schedule->lock = xSemaphoreCreateMutex();
	if (!schedule->lock) {
		free(schedule);
		return ESP_ERR_NO_MEM;
	}
	strcpy(schedule->nvs_namespace, options->nvs_namespace);
	strcpy(schedule->nvs_key, options->nvs_key);
	snprintf(schedule->task_name, sizeof(schedule->task_name), "%s",
		 options->task_name ? options->task_name : "weekly_sched");
	schedule->blob_magic = options->blob_magic;
	schedule->max_action = options->max_action;
	schedule->catch_up_on_clock_ready = options->catch_up_on_clock_ready;
	schedule->stage_timeout_ms = options->stage_timeout_ms ?
		options->stage_timeout_ms : DEFAULT_STAGE_TIMEOUT_MS;
	schedule->task_period_ms = options->task_period_ms ?
		options->task_period_ms : DEFAULT_TASK_PERIOD_MS;
	schedule->task_stack_words = options->task_stack_words ?
		options->task_stack_words : DEFAULT_TASK_STACK_WORDS;
	schedule->task_priority = options->task_priority ?
		options->task_priority : DEFAULT_TASK_PRIORITY;
	schedule->apply = options->apply;
	schedule->user = options->user;
	load_config(schedule);
	for (size_t i = 0; i < KEEMASH_WEEKLY_SCHEDULE_MAX_POINTS; i++) {
		schedule->last_run_day[i] = UINT32_MAX;
	}
	schedule->catch_up_pending = schedule->config.enabled;
	schedule->last_apply_index = KEEMASH_WEEKLY_SCHEDULE_NO_INDEX;
	schedule->last_apply_kind = KEEMASH_WEEKLY_SCHEDULE_APPLY_NONE;
	if (xTaskCreate(schedule_task, schedule->task_name,
			schedule->task_stack_words, schedule,
			schedule->task_priority, &schedule->task) != pdPASS) {
		vSemaphoreDelete(schedule->lock);
		free(schedule);
		return ESP_ERR_NO_MEM;
	}
	*out = schedule;
	ESP_LOGI(TAG, "ready enabled=%u persist=%u points=%u generation=%lu",
		 schedule->config.enabled ? 1U : 0U,
		 schedule->config.persistence_enabled ? 1U : 0U,
		 (unsigned)schedule->config.count,
		 (unsigned long)schedule->config.generation);
	return ESP_OK;
}

void keemash_weekly_schedule_stop(keemash_weekly_schedule_t *schedule)
{
	if (!schedule) return;
	if (schedule->task) vTaskDelete(schedule->task);
	if (schedule->lock) vSemaphoreDelete(schedule->lock);
	free(schedule);
}

esp_err_t keemash_weekly_schedule_stage_begin(
	keemash_weekly_schedule_t *schedule, uint32_t generation,
	uint8_t count, bool enabled, bool persistence_enabled)
{
	if (!schedule || generation == 0 ||
	    count > KEEMASH_WEEKLY_SCHEDULE_MAX_POINTS) return ESP_ERR_INVALID_ARG;
	if (xSemaphoreTake(schedule->lock, pdMS_TO_TICKS(500)) != pdTRUE) {
		return ESP_ERR_TIMEOUT;
	}
	memset(&schedule->stage, 0, sizeof(schedule->stage));
	schedule->stage.active = true;
	schedule->stage.started_ms = monotonic_ms();
	schedule->stage.config.generation = generation;
	schedule->stage.config.count = count;
	schedule->stage.config.enabled = enabled;
	schedule->stage.config.persistence_enabled = persistence_enabled;
	xSemaphoreGive(schedule->lock);
	return ESP_OK;
}

esp_err_t keemash_weekly_schedule_stage_point(
	keemash_weekly_schedule_t *schedule, uint32_t generation,
	uint8_t index, const keemash_weekly_schedule_point_t *point)
{
	if (!schedule || !point || !point_valid(schedule, point)) {
		return ESP_ERR_INVALID_ARG;
	}
	if (xSemaphoreTake(schedule->lock, pdMS_TO_TICKS(500)) != pdTRUE) {
		return ESP_ERR_TIMEOUT;
	}
	expire_stage_locked(schedule, monotonic_ms());
	if (!schedule->stage.active ||
	    schedule->stage.config.generation != generation ||
	    index >= schedule->stage.config.count) {
		xSemaphoreGive(schedule->lock);
		return ESP_ERR_INVALID_STATE;
	}
	schedule->stage.config.points[index] = *point;
	schedule->stage.received_mask |= (uint8_t)(1U << index);
	xSemaphoreGive(schedule->lock);
	return ESP_OK;
}

esp_err_t keemash_weekly_schedule_stage_commit(
	keemash_weekly_schedule_t *schedule, uint32_t generation)
{
	if (!schedule) return ESP_ERR_INVALID_STATE;
	if (xSemaphoreTake(schedule->lock, pdMS_TO_TICKS(500)) != pdTRUE) {
		return ESP_ERR_TIMEOUT;
	}
	expire_stage_locked(schedule, monotonic_ms());
	uint8_t expected = schedule->stage.config.count == 0 ? 0U :
		(uint8_t)((1U << schedule->stage.config.count) - 1U);
	if (!schedule->stage.active ||
	    schedule->stage.config.generation != generation ||
	    schedule->stage.received_mask != expected ||
	    !config_valid(schedule, &schedule->stage.config)) {
		xSemaphoreGive(schedule->lock);
		return ESP_ERR_INVALID_STATE;
	}
	keemash_weekly_schedule_config_t candidate = schedule->stage.config;
	esp_err_t err = persist_config(schedule, &candidate);
	if (err != ESP_OK) {
		schedule->last_error = err;
		xSemaphoreGive(schedule->lock);
		return err;
	}
	schedule->config = candidate;
	memset(&schedule->stage, 0, sizeof(schedule->stage));
	for (size_t i = 0; i < KEEMASH_WEEKLY_SCHEDULE_MAX_POINTS; i++) {
		schedule->last_run_day[i] = UINT32_MAX;
	}
	schedule->catch_up_pending = schedule->config.enabled;
	schedule->retry_pending = false;
	schedule->next_retry_ms = 0;
	schedule->last_apply_valid = false;
	schedule->last_apply_index = KEEMASH_WEEKLY_SCHEDULE_NO_INDEX;
	schedule->last_apply_kind = KEEMASH_WEEKLY_SCHEDULE_APPLY_NONE;
	schedule->last_error = ESP_OK;
	xSemaphoreGive(schedule->lock);
	return ESP_OK;
}

void keemash_weekly_schedule_get_status(
	keemash_weekly_schedule_t *schedule,
	keemash_weekly_schedule_status_t *status)
{
	if (!status) return;
	memset(status, 0, sizeof(*status));
	status->local_weekday = KEEMASH_WEEKLY_SCHEDULE_NO_INDEX;
	status->local_minute = UINT16_MAX;
	status->active_index = KEEMASH_WEEKLY_SCHEDULE_NO_INDEX;
	status->next_index = KEEMASH_WEEKLY_SCHEDULE_NO_INDEX;
	status->next_in_minutes = UINT16_MAX;
	status->last_apply_index = KEEMASH_WEEKLY_SCHEDULE_NO_INDEX;
	status->last_apply_kind = KEEMASH_WEEKLY_SCHEDULE_APPLY_NONE;
	status->last_apply_age_ms = UINT32_MAX;
	status->time_sync_age_ms = UINT32_MAX;
	if (!schedule ||
	    xSemaphoreTake(schedule->lock, pdMS_TO_TICKS(100)) != pdTRUE) {
		status->last_error = schedule ? ESP_ERR_TIMEOUT : ESP_ERR_INVALID_STATE;
		return;
	}
	status->config = schedule->config;
	status->catch_up_pending = schedule->catch_up_pending;
	status->last_apply_valid = schedule->last_apply_valid;
	status->last_apply_index = schedule->last_apply_index;
	status->last_apply_kind = schedule->last_apply_kind;
	status->last_apply_age_ms = schedule->last_apply_valid ?
		monotonic_ms() - schedule->last_apply_ms : UINT32_MAX;
	status->last_error = schedule->last_error;
	xSemaphoreGive(schedule->lock);
	struct tm local = {0};
	status->clock_valid = clock_snapshot(&local, NULL);
	keemash_mesh_time_status_t time_status = {0};
	keemash_mesh_time_get_status(&time_status);
	status->time_sync_age_ms = time_status.last_sync_age_ms;
	if (status->clock_valid) {
		status->local_weekday = weekday_index(&local);
		status->local_minute = (uint16_t)(local.tm_hour * 60 + local.tm_min);
	}
	if (!status->clock_valid || !status->config.enabled) return;
	status->active_index = latest_point_index(&status->config,
		status->local_weekday, status->local_minute);
	status->next_index = next_point_index(&status->config,
		status->local_weekday, status->local_minute,
					    &status->next_in_minutes);
}
