// SPDX-License-Identifier: GPL-2.0-only

#include "keemash_ota_v3_checkpoint.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "esp_rom_crc.h"
#include "nvs.h"
#include "sdkconfig.h"

#define CHECKPOINT_MAGIC 0x334f544bU
#define CHECKPOINT_VERSION 1U
#define CHECKPOINT_NAMESPACE "km_ota3"

#ifdef CONFIG_KEEMASH_OTA_V3_CHECKPOINT_BYTES
#define CHECKPOINT_INTERVAL CONFIG_KEEMASH_OTA_V3_CHECKPOINT_BYTES
#else
#define CHECKPOINT_INTERVAL 65536U
#endif

_Static_assert(CHECKPOINT_INTERVAL % KEEMASH_OTA_V3_FULL_BLOCK_SIZE == 0U,
	       "OTA v3 checkpoint interval must align to a full block");

typedef struct {
	uint32_t magic;
	uint16_t version;
	uint8_t tombstone;
	uint8_t reserved;
	uint32_t generation;
	keemash_ota_v3_checkpoint_t checkpoint;
	uint32_t crc32;
} stored_checkpoint_t;

_Static_assert(sizeof(stored_checkpoint_t) < 2048U,
	       "OTA v3 checkpoint must fit in bounded NVS storage");

static const char *checkpoint_key(uint32_t generation)
{
	return (generation & 1U) ? "v3a" : "v3b";
}

static bool record_valid(const stored_checkpoint_t *record)
{
	if (record->magic != CHECKPOINT_MAGIC ||
	    record->version != CHECKPOINT_VERSION ||
	    record->tombstone > 1U || record->generation == 0U) {
		return false;
	}
	uint32_t crc = esp_rom_crc32_le(0U, (const uint8_t *)record,
					 offsetof(stored_checkpoint_t, crc32));
	if (crc != record->crc32) return false;
	if (record->tombstone) return true;
	const keemash_ota_v3_checkpoint_t *cp = &record->checkpoint;
	return cp->signed_fields_len > 0U &&
		cp->signed_fields_len <= KEEMASH_OTA_V3_SIGNED_FIELDS_MAX &&
		cp->partition_label[0] != '\0' &&
		memchr(cp->partition_label, '\0', sizeof(cp->partition_label)) != NULL &&
		cp->resume.next_block_index > 0U &&
		cp->resume.next_block_index < KEEMASH_OTA_V3_MAX_BLOCK_COUNT &&
		cp->resume.raw_offset > 0U &&
		cp->resume.raw_offset % CHECKPOINT_INTERVAL == 0U &&
		(uint64_t)cp->resume.next_block_index *
			KEEMASH_OTA_V3_FULL_BLOCK_SIZE == cp->resume.raw_offset &&
		cp->resume.raw_offset <= KEEMASH_OTA_V3_MAX_IMAGE_SIZE &&
		cp->resume.encoded_offset > 0U &&
		cp->resume.encoded_offset <= KEEMASH_OTA_V3_MAX_PACKAGE_SIZE;
}

static bool read_record(nvs_handle_t nvs, const char *key,
			stored_checkpoint_t *record)
{
	size_t length = sizeof(*record);
	return nvs_get_blob(nvs, key, record, &length) == ESP_OK &&
		length == sizeof(*record) && record_valid(record);
}

static bool newer(uint32_t a, uint32_t b)
{
	return (int32_t)(a - b) > 0;
}

static esp_err_t latest_record(nvs_handle_t nvs,
			       stored_checkpoint_t *latest, bool *found)
{
	stored_checkpoint_t *other = malloc(sizeof(*other));
	if (!other) return ESP_ERR_NO_MEM;
	bool has_first = read_record(nvs, "v3a", latest);
	bool has_second = read_record(nvs, "v3b", other);
	if (has_second && (!has_first ||
	    newer(other->generation, latest->generation))) {
		*latest = *other;
	}
	*found = has_first || has_second;
	free(other);
	return ESP_OK;
}

esp_err_t keemash_ota_v3_checkpoint_load(
	keemash_ota_v3_checkpoint_t *checkpoint)
{
	if (!checkpoint) return ESP_ERR_INVALID_ARG;
	nvs_handle_t nvs;
	esp_err_t err = nvs_open(CHECKPOINT_NAMESPACE, NVS_READONLY, &nvs);
	if (err == ESP_ERR_NVS_NOT_FOUND) return ESP_ERR_NOT_FOUND;
	if (err != ESP_OK) return err;
	stored_checkpoint_t *latest = calloc(1U, sizeof(*latest));
	if (!latest) {
		nvs_close(nvs);
		return ESP_ERR_NO_MEM;
	}
	bool found = false;
	err = latest_record(nvs, latest, &found);
	nvs_close(nvs);
	if (err == ESP_OK && found && !latest->tombstone) {
		*checkpoint = latest->checkpoint;
	}
	bool available = found && !latest->tombstone;
	free(latest);
	if (err != ESP_OK) return err;
	if (!available) return ESP_ERR_NOT_FOUND;
	return ESP_OK;
}

static esp_err_t write_record(const keemash_ota_v3_checkpoint_t *checkpoint,
			      bool tombstone)
{
	nvs_handle_t nvs;
	esp_err_t err = nvs_open(CHECKPOINT_NAMESPACE, NVS_READWRITE, &nvs);
	if (err != ESP_OK) return err;
	stored_checkpoint_t *record = calloc(1U, sizeof(*record));
	if (!record) {
		nvs_close(nvs);
		return ESP_ERR_NO_MEM;
	}
	bool found = false;
	err = latest_record(nvs, record, &found);
	if (err != ESP_OK) {
		free(record);
		nvs_close(nvs);
		return err;
	}
	uint32_t next_generation = found ? record->generation + 1U : 1U;
	if (next_generation == 0U) next_generation = 1U;
	memset(record, 0, sizeof(*record));
	record->magic = CHECKPOINT_MAGIC;
	record->version = CHECKPOINT_VERSION;
	record->tombstone = tombstone ? 1U : 0U;
	record->generation = next_generation;
	if (!tombstone) record->checkpoint = *checkpoint;
	record->crc32 = esp_rom_crc32_le(0U, (const uint8_t *)record,
					 offsetof(stored_checkpoint_t, crc32));
	err = nvs_set_blob(nvs, checkpoint_key(record->generation),
			   record, sizeof(*record));
	if (err == ESP_OK) err = nvs_commit(nvs);
	free(record);
	nvs_close(nvs);
	return err;
}

esp_err_t keemash_ota_v3_checkpoint_save(
	const keemash_ota_v3_checkpoint_t *checkpoint)
{
	if (!checkpoint || checkpoint->signed_fields_len == 0U ||
	    checkpoint->signed_fields_len > KEEMASH_OTA_V3_SIGNED_FIELDS_MAX ||
	    checkpoint->partition_label[0] == '\0' ||
	    memchr(checkpoint->partition_label, '\0',
		   sizeof(checkpoint->partition_label)) == NULL ||
	    checkpoint->resume.next_block_index == 0U ||
	    checkpoint->resume.next_block_index >= KEEMASH_OTA_V3_MAX_BLOCK_COUNT ||
	    checkpoint->resume.raw_offset == 0U ||
	    checkpoint->resume.raw_offset % CHECKPOINT_INTERVAL != 0U ||
	    (uint64_t)checkpoint->resume.next_block_index *
		KEEMASH_OTA_V3_FULL_BLOCK_SIZE != checkpoint->resume.raw_offset ||
	    checkpoint->resume.raw_offset > KEEMASH_OTA_V3_MAX_IMAGE_SIZE ||
	    checkpoint->resume.encoded_offset == 0U ||
	    checkpoint->resume.encoded_offset > KEEMASH_OTA_V3_MAX_PACKAGE_SIZE) {
		return ESP_ERR_INVALID_ARG;
	}
	return write_record(checkpoint, false);
}

esp_err_t keemash_ota_v3_checkpoint_clear(void)
{
	return write_record(NULL, true);
}
