// SPDX-License-Identifier: GPL-2.0-only

#include "keemash_ota_v3.h"

#include <string.h>

#ifdef CONFIG_KEEMASH_OTA_V3_CHECKPOINT_BYTES
#define OTA_V3_CHECKPOINT_BYTES CONFIG_KEEMASH_OTA_V3_CHECKPOINT_BYTES
#else
#define OTA_V3_CHECKPOINT_BYTES 65536U
#endif

_Static_assert(OTA_V3_CHECKPOINT_BYTES % KEEMASH_OTA_V3_FULL_BLOCK_SIZE == 0U,
	       "OTA v3 checkpoint must align to a full block");

static esp_err_t stream_fail(keemash_ota_v3_stream_t *stream, esp_err_t error)
{
	stream->failed = true;
	keemash_ota_v3_inflater_end(&stream->inflater);
	stream->block_active = false;
	return error;
}

static esp_err_t stream_output(const uint8_t *bytes, size_t length, void *context)
{
	keemash_ota_v3_stream_t *stream = context;
	if (mbedtls_md_update(&stream->block_raw_hash, bytes, length) != 0 ||
	    mbedtls_md_update(&stream->image_hash, bytes, length) != 0) {
		return ESP_FAIL;
	}
	return stream->output_fn(bytes, length, stream->output_context);
}

esp_err_t keemash_ota_v3_stream_begin(
	keemash_ota_v3_stream_t *stream,
	const keemash_ota_v3_signed_fields_t *verified_fields,
	keemash_ota_v3_output_fn output_fn, void *output_context)
{
	if (!stream || !verified_fields || !output_fn ||
	    verified_fields->codec !=
		keemash_fabric_v2_FirmwareArtifactCodec_ARTIFACT_CODEC_FULL_DEFLATE ||
	    verified_fields->block_size != KEEMASH_OTA_V3_FULL_BLOCK_SIZE ||
	    verified_fields->block_count == 0U) {
		return ESP_ERR_INVALID_ARG;
	}
	memset(stream, 0, sizeof(*stream));
	stream->fields = *verified_fields;
	stream->output_fn = output_fn;
	stream->output_context = output_context;
	const mbedtls_md_info_t *sha256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (!sha256) return stream_fail(stream, ESP_FAIL);
	mbedtls_md_init(&stream->image_hash);
	mbedtls_md_init(&stream->payload_hash);
	mbedtls_md_init(&stream->block_raw_hash);
	mbedtls_md_init(&stream->block_encoded_hash);
	if (mbedtls_md_setup(&stream->image_hash, sha256, 0) != 0 ||
	    mbedtls_md_setup(&stream->payload_hash, sha256, 0) != 0 ||
	    mbedtls_md_setup(&stream->block_raw_hash, sha256, 0) != 0 ||
	    mbedtls_md_setup(&stream->block_encoded_hash, sha256, 0) != 0 ||
	    mbedtls_md_starts(&stream->image_hash) != 0 ||
	    mbedtls_md_starts(&stream->payload_hash) != 0) {
		return stream_fail(stream, ESP_FAIL);
	}
	stream->payload_hash_complete = true;
	return ESP_OK;
}

esp_err_t keemash_ota_v3_stream_resume(
	keemash_ota_v3_stream_t *stream,
	const keemash_ota_v3_signed_fields_t *verified_fields,
	const keemash_ota_v3_resume_point_t *resume_point,
	keemash_ota_v3_read_fn read_fn, void *read_context,
	keemash_ota_v3_output_fn output_fn, void *output_context)
{
	if (!stream || !verified_fields || !resume_point || !read_fn ||
	    resume_point->next_block_index == 0U ||
	    resume_point->next_block_index >= verified_fields->block_count ||
	    (uint64_t)resume_point->next_block_index * verified_fields->block_size !=
		resume_point->raw_offset ||
	    resume_point->raw_offset >= verified_fields->raw_size ||
	    resume_point->encoded_offset == 0U ||
	    resume_point->encoded_offset >= verified_fields->encoded_size) {
		return ESP_ERR_INVALID_ARG;
	}
	esp_err_t err = keemash_ota_v3_stream_begin(
		stream, verified_fields, output_fn, output_context);
	if (err != ESP_OK) return err;

	uint8_t buffer[KEEMASH_OTA_V3_INFLATE_OUTPUT_BYTES];
	for (uint32_t offset = 0U; offset < resume_point->raw_offset;) {
		size_t length = resume_point->raw_offset - offset;
		if (length > sizeof(buffer)) length = sizeof(buffer);
		err = read_fn(offset, buffer, length, read_context);
		if (err != ESP_OK ||
		    mbedtls_md_update(&stream->image_hash, buffer, length) != 0) {
			return stream_fail(stream, err == ESP_OK ? ESP_FAIL : err);
		}
		offset += (uint32_t)length;
	}
	mbedtls_md_context_t prefix = {0};
	const mbedtls_md_info_t *sha256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	uint8_t prefix_hash[KEEMASH_OTA_V3_SHA256_LEN];
	mbedtls_md_init(&prefix);
	if (!sha256 || mbedtls_md_setup(&prefix, sha256, 0) != 0 ||
	    mbedtls_md_clone(&prefix, &stream->image_hash) != 0 ||
	    mbedtls_md_finish(&prefix, prefix_hash) != 0) {
		mbedtls_md_free(&prefix);
		return stream_fail(stream, ESP_FAIL);
	}
	mbedtls_md_free(&prefix);
	if (memcmp(prefix_hash, resume_point->image_prefix_sha256,
		   KEEMASH_OTA_V3_SHA256_LEN) != 0) {
		return stream_fail(stream, ESP_ERR_INVALID_CRC);
	}
	stream->next_block_index = resume_point->next_block_index;
	stream->raw_offset = resume_point->raw_offset;
	stream->encoded_offset = resume_point->encoded_offset;
	memcpy(stream->block_chain, resume_point->block_chain,
	       KEEMASH_OTA_V3_SHA256_LEN);
	stream->payload_hash_complete = false;
	return ESP_OK;
}

esp_err_t keemash_ota_v3_stream_checkpoint(
	const keemash_ota_v3_stream_t *stream,
	keemash_ota_v3_resume_point_t *resume_point)
{
	if (!stream || !resume_point || stream->failed || stream->finished ||
	    stream->block_active || stream->next_block_index == 0U ||
	    stream->next_block_index >= stream->fields.block_count ||
	    stream->raw_offset % OTA_V3_CHECKPOINT_BYTES != 0U) {
		return ESP_ERR_INVALID_STATE;
	}
	mbedtls_md_context_t prefix = {0};
	const mbedtls_md_info_t *sha256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	mbedtls_md_init(&prefix);
	if (!sha256 || mbedtls_md_setup(&prefix, sha256, 0) != 0 ||
	    mbedtls_md_clone(&prefix, &stream->image_hash) != 0 ||
	    mbedtls_md_finish(&prefix, resume_point->image_prefix_sha256) != 0) {
		mbedtls_md_free(&prefix);
		return ESP_FAIL;
	}
	mbedtls_md_free(&prefix);
	resume_point->next_block_index = stream->next_block_index;
	resume_point->raw_offset = stream->raw_offset;
	resume_point->encoded_offset = stream->encoded_offset;
	memcpy(resume_point->block_chain, stream->block_chain,
	       KEEMASH_OTA_V3_SHA256_LEN);
	return ESP_OK;
}

static bool same_descriptor(
	const keemash_fabric_v2_FirmwareBlockDescriptor *a,
	const keemash_fabric_v2_FirmwareBlockDescriptor *b)
{
	return a->index == b->index && a->raw_offset == b->raw_offset &&
		a->encoded_offset == b->encoded_offset &&
		a->raw_size == b->raw_size && a->encoded_size == b->encoded_size &&
		a->kind == b->kind && a->raw_sha256.size == 32U &&
		b->raw_sha256.size == 32U && a->encoded_sha256.size == 32U &&
		b->encoded_sha256.size == 32U &&
		memcmp(a->raw_sha256.bytes, b->raw_sha256.bytes, 32U) == 0 &&
		memcmp(a->encoded_sha256.bytes, b->encoded_sha256.bytes, 32U) == 0;
}

static esp_err_t start_block(
	keemash_ota_v3_stream_t *stream,
	const keemash_fabric_v2_FirmwareBlockDescriptor *descriptor)
{
	uint8_t next_chain[KEEMASH_OTA_V3_SHA256_LEN];
	esp_err_t err = keemash_ota_v3_check_block_descriptor(
		&stream->fields, descriptor, stream->next_block_index,
		stream->raw_offset, stream->encoded_offset,
		stream->block_chain, next_chain);
	if (err != ESP_OK) return err;
	if (descriptor->kind !=
	    keemash_fabric_v2_FirmwareBlockKind_FIRMWARE_BLOCK_DEFLATE) {
		return ESP_ERR_NOT_SUPPORTED;
	}
	stream->block = *descriptor;
	memcpy(stream->block_chain, next_chain, sizeof(next_chain));
	stream->block_encoded_offset = 0U;
	if (mbedtls_md_starts(&stream->block_raw_hash) != 0 ||
	    mbedtls_md_starts(&stream->block_encoded_hash) != 0) {
		return ESP_FAIL;
	}
	err = keemash_ota_v3_inflater_begin(
		&stream->inflater, descriptor->raw_size, stream_output, stream);
	if (err == ESP_OK) stream->block_active = true;
	return err;
}

static esp_err_t finish_block(keemash_ota_v3_stream_t *stream)
{
	uint8_t raw_hash[32];
	uint8_t encoded_hash[32];
	if (mbedtls_md_finish(&stream->block_raw_hash, raw_hash) != 0 ||
	    mbedtls_md_finish(&stream->block_encoded_hash, encoded_hash) != 0) {
		return ESP_FAIL;
	}
	if (memcmp(raw_hash, stream->block.raw_sha256.bytes, 32U) != 0 ||
	    memcmp(encoded_hash, stream->block.encoded_sha256.bytes, 32U) != 0) {
		return ESP_ERR_INVALID_CRC;
	}
	stream->raw_offset += stream->block.raw_size;
	stream->encoded_offset += stream->block.encoded_size;
	stream->block_encoded_offset = 0U;
	stream->next_block_index++;
	stream->block_active = false;
	keemash_ota_v3_inflater_end(&stream->inflater);
	return ESP_OK;
}

esp_err_t keemash_ota_v3_stream_feed(
	keemash_ota_v3_stream_t *stream,
	const keemash_fabric_v2_FirmwareBlockDescriptor *descriptor,
	uint32_t block_encoded_offset, const uint8_t *chunk,
	size_t chunk_size, bool final_chunk)
{
	if (!stream || stream->failed || stream->finished || !descriptor || !chunk ||
	    chunk_size == 0U || chunk_size > KEEMASH_OTA_V3_MAX_CHUNK_BYTES) {
		return ESP_ERR_INVALID_ARG;
	}
	uint8_t chunk_hash[32];
	const mbedtls_md_info_t *sha256 = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (!sha256 || mbedtls_md(sha256, chunk, chunk_size, chunk_hash) != 0) {
		return stream_fail(stream, ESP_FAIL);
	}
	if (stream->last_chunk_valid && descriptor->index == stream->last_chunk_index &&
	    block_encoded_offset == stream->last_chunk_offset) {
		return same_descriptor(&stream->last_chunk_block, descriptor) &&
		       stream->last_chunk_size == chunk_size &&
		       stream->last_chunk_final == final_chunk &&
		       memcmp(stream->last_chunk_hash, chunk_hash, 32U) == 0
			? ESP_OK : stream_fail(stream, ESP_ERR_INVALID_CRC);
	}
	if (!stream->block_active) {
		if (block_encoded_offset != 0U) {
			return stream_fail(stream, ESP_ERR_INVALID_ARG);
		}
		esp_err_t err = start_block(stream, descriptor);
		if (err != ESP_OK) return stream_fail(stream, err);
	} else if (!same_descriptor(&stream->block, descriptor)) {
		return stream_fail(stream, ESP_ERR_INVALID_ARG);
	}
	if (block_encoded_offset != stream->block_encoded_offset ||
	    chunk_size > stream->block.encoded_size - stream->block_encoded_offset ||
	    final_chunk != (chunk_size ==
		stream->block.encoded_size - stream->block_encoded_offset)) {
		return stream_fail(stream, ESP_ERR_INVALID_SIZE);
	}
	if (mbedtls_md_update(&stream->block_encoded_hash, chunk, chunk_size) != 0 ||
	    mbedtls_md_update(&stream->payload_hash, chunk, chunk_size) != 0) {
		return stream_fail(stream, ESP_FAIL);
	}
	esp_err_t err = keemash_ota_v3_inflater_feed(
		&stream->inflater, chunk, chunk_size, final_chunk);
	if (err != ESP_OK) return stream_fail(stream, err);
	stream->block_encoded_offset += (uint32_t)chunk_size;
	if (final_chunk) {
		err = finish_block(stream);
		if (err != ESP_OK) return stream_fail(stream, err);
	}
	stream->last_chunk_index = descriptor->index;
	stream->last_chunk_block = *descriptor;
	stream->last_chunk_offset = block_encoded_offset;
	stream->last_chunk_size = (uint32_t)chunk_size;
	stream->last_chunk_final = final_chunk;
	memcpy(stream->last_chunk_hash, chunk_hash, 32U);
	stream->last_chunk_valid = true;
	return ESP_OK;
}

esp_err_t keemash_ota_v3_stream_finish(keemash_ota_v3_stream_t *stream)
{
	if (!stream || stream->failed || stream->finished || stream->block_active ||
	    stream->next_block_index != stream->fields.block_count ||
	    stream->raw_offset != stream->fields.raw_size ||
	    stream->encoded_offset != stream->fields.encoded_size) {
		return ESP_ERR_INVALID_STATE;
	}
	uint8_t image_hash[32];
	uint8_t payload_hash[32];
	if (mbedtls_md_finish(&stream->image_hash, image_hash) != 0 ||
	    mbedtls_md_finish(&stream->payload_hash, payload_hash) != 0) {
		return stream_fail(stream, ESP_FAIL);
	}
	if (memcmp(image_hash, stream->fields.image_sha256, 32U) != 0 ||
	    (stream->payload_hash_complete &&
	     memcmp(payload_hash, stream->fields.encoded_sha256, 32U) != 0) ||
	    memcmp(stream->block_chain, stream->fields.block_table_sha256, 32U) != 0) {
		return stream_fail(stream, ESP_ERR_INVALID_CRC);
	}
	stream->finished = true;
	return ESP_OK;
}

void keemash_ota_v3_stream_end(keemash_ota_v3_stream_t *stream)
{
	if (!stream) return;
	keemash_ota_v3_inflater_end(&stream->inflater);
	mbedtls_md_free(&stream->image_hash);
	mbedtls_md_free(&stream->payload_hash);
	mbedtls_md_free(&stream->block_raw_hash);
	mbedtls_md_free(&stream->block_encoded_hash);
	memset(stream, 0, sizeof(*stream));
}
