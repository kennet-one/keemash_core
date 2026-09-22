// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "keelink-fabric-v2.pb.h"
#include "mbedtls/md.h"
#include "zlib.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KEEMASH_OTA_V3_SCHEMA_VERSION 1U
#define KEEMASH_OTA_V3_SHA256_LEN 32U
#define KEEMASH_OTA_V3_SIGNATURE_LEN 64U
#define KEEMASH_OTA_V3_PUBLIC_KEY_LEN 65U
#define KEEMASH_OTA_V3_FULL_BLOCK_SIZE 16384U
#define KEEMASH_OTA_V3_DELTA_BLOCK_SIZE 8192U
#define KEEMASH_OTA_V3_DEFLATE_WINDOW_BITS 11U
#define KEEMASH_OTA_V3_MAX_IMAGE_SIZE (8U * 1024U * 1024U)
#define KEEMASH_OTA_V3_MAX_PACKAGE_SIZE (16U * 1024U * 1024U)
#define KEEMASH_OTA_V3_MAX_BLOCK_COUNT 1024U
#define KEEMASH_OTA_V3_INFLATE_OUTPUT_BYTES 2048U
#define KEEMASH_OTA_V3_MAX_CHUNK_BYTES 2048U

typedef esp_err_t (*keemash_ota_v3_output_fn)(
	const uint8_t *bytes, size_t length, void *context);

typedef esp_err_t (*keemash_ota_v3_read_fn)(
	uint32_t offset, uint8_t *bytes, size_t length, void *context);

typedef struct {
	z_stream stream;
	uint8_t output[KEEMASH_OTA_V3_INFLATE_OUTPUT_BYTES];
	uint32_t expected_raw_size;
	uint32_t produced_raw_size;
	keemash_ota_v3_output_fn output_fn;
	void *output_context;
	bool active;
} keemash_ota_v3_inflater_t;

typedef struct {
	uint32_t schema_version;
	char project_name[33];
	char chip_target[17];
	char firmware_version[33];
	char build_commit[41];
	char signing_key_id[33];
	uint32_t minimum_core_version;
	uint32_t minimum_fabric_schema;
	uint32_t raw_size;
	uint32_t encoded_size;
	uint32_t required_app_slot_size;
	uint32_t codec;
	uint32_t block_size;
	uint32_t block_count;
	uint32_t deflate_window_bits;
	uint8_t image_sha256[KEEMASH_OTA_V3_SHA256_LEN];
	uint8_t encoded_sha256[KEEMASH_OTA_V3_SHA256_LEN];
	uint8_t block_table_sha256[KEEMASH_OTA_V3_SHA256_LEN];
	uint8_t base_image_sha256[KEEMASH_OTA_V3_SHA256_LEN];
	bool has_base_image;
} keemash_ota_v3_signed_fields_t;

esp_err_t keemash_ota_v3_verify_signed_fields(
	const uint8_t *signed_fields, size_t signed_fields_len,
	const uint8_t *signature, size_t signature_len,
	keemash_ota_v3_signed_fields_t *out);

esp_err_t keemash_ota_v3_check_target(
	const keemash_ota_v3_signed_fields_t *fields,
	const char *project_name, const char *chip_target,
	uint32_t app_slot_size, uint32_t core_version,
	uint32_t fabric_schema);

esp_err_t keemash_ota_v3_encode_transfer(
	const keemash_fabric_v2_OtaTransfer *message,
	uint8_t *out, size_t capacity, size_t *written);

esp_err_t keemash_ota_v3_decode_transfer(
	const uint8_t *data, size_t length,
	keemash_fabric_v2_OtaTransfer *message);

esp_err_t keemash_ota_v3_encode_block_descriptor(
	const keemash_fabric_v2_FirmwareBlockDescriptor *descriptor,
	uint8_t *out, size_t capacity, size_t *written,
	bool length_delimited);

esp_err_t keemash_ota_v3_check_block_descriptor(
	const keemash_ota_v3_signed_fields_t *fields,
	const keemash_fabric_v2_FirmwareBlockDescriptor *descriptor,
	uint32_t expected_index, uint32_t expected_raw_offset,
	uint32_t expected_encoded_offset,
	const uint8_t previous_chain[KEEMASH_OTA_V3_SHA256_LEN],
	uint8_t next_chain[KEEMASH_OTA_V3_SHA256_LEN]);

esp_err_t keemash_ota_v3_inflater_begin(
	keemash_ota_v3_inflater_t *inflater, uint32_t expected_raw_size,
	keemash_ota_v3_output_fn output_fn, void *output_context);

esp_err_t keemash_ota_v3_inflater_feed(
	keemash_ota_v3_inflater_t *inflater, const uint8_t *encoded,
	size_t encoded_size, bool final_chunk);

void keemash_ota_v3_inflater_end(keemash_ota_v3_inflater_t *inflater);

typedef struct {
	uint32_t next_block_index;
	uint32_t raw_offset;
	uint32_t encoded_offset;
	uint8_t block_chain[KEEMASH_OTA_V3_SHA256_LEN];
	uint8_t image_prefix_sha256[KEEMASH_OTA_V3_SHA256_LEN];
} keemash_ota_v3_resume_point_t;

typedef struct {
	keemash_ota_v3_signed_fields_t fields;
	keemash_ota_v3_inflater_t inflater;
	mbedtls_md_context_t image_hash;
	mbedtls_md_context_t payload_hash;
	mbedtls_md_context_t block_raw_hash;
	mbedtls_md_context_t block_encoded_hash;
	keemash_fabric_v2_FirmwareBlockDescriptor block;
	keemash_fabric_v2_FirmwareBlockDescriptor last_chunk_block;
	keemash_ota_v3_output_fn output_fn;
	void *output_context;
	uint8_t block_chain[KEEMASH_OTA_V3_SHA256_LEN];
	uint8_t last_chunk_hash[KEEMASH_OTA_V3_SHA256_LEN];
	uint32_t raw_offset;
	uint32_t encoded_offset;
	uint32_t block_encoded_offset;
	uint32_t next_block_index;
	uint32_t last_chunk_index;
	uint32_t last_chunk_offset;
	uint32_t last_chunk_size;
	bool block_active;
	bool last_chunk_valid;
	bool last_chunk_final;
	bool failed;
	bool finished;
	bool payload_hash_complete;
} keemash_ota_v3_stream_t;

esp_err_t keemash_ota_v3_stream_begin(
	keemash_ota_v3_stream_t *stream,
	const keemash_ota_v3_signed_fields_t *verified_fields,
	keemash_ota_v3_output_fn output_fn, void *output_context);

esp_err_t keemash_ota_v3_stream_resume(
	keemash_ota_v3_stream_t *stream,
	const keemash_ota_v3_signed_fields_t *verified_fields,
	const keemash_ota_v3_resume_point_t *resume_point,
	keemash_ota_v3_read_fn read_fn, void *read_context,
	keemash_ota_v3_output_fn output_fn, void *output_context);

esp_err_t keemash_ota_v3_stream_checkpoint(
	const keemash_ota_v3_stream_t *stream,
	keemash_ota_v3_resume_point_t *resume_point);

esp_err_t keemash_ota_v3_stream_feed(
	keemash_ota_v3_stream_t *stream,
	const keemash_fabric_v2_FirmwareBlockDescriptor *descriptor,
	uint32_t block_encoded_offset, const uint8_t *chunk,
	size_t chunk_size, bool final_chunk);

esp_err_t keemash_ota_v3_stream_finish(keemash_ota_v3_stream_t *stream);

void keemash_ota_v3_stream_end(keemash_ota_v3_stream_t *stream);

/* Validate a complete full-deflate .kota3 package via bounded random reads.
 * The caller must serialize writes to the underlying storage during this call.
 * This does not install the image or authorize a target-specific deployment. */
esp_err_t keemash_ota_v3_verify_package(
	keemash_ota_v3_read_fn read_fn, void *read_context,
	uint32_t package_size, keemash_ota_v3_signed_fields_t *out);

#ifdef __cplusplus
}
#endif
