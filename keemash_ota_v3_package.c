// SPDX-License-Identifier: GPL-2.0-only

#include "keemash_ota_v3.h"

#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "pb_decode.h"

#define KOTA3_HEADER_SIZE 16U
#define KOTA3_MANIFEST_MAX (64U * 1024U)
#define KOTA3_READ_BYTES 2048U

static const uint8_t s_magic[8] = {'K', 'O', 'T', 'A', '3', 0, 0, 1};

typedef struct {
	keemash_ota_v3_read_fn read;
	void *context;
	uint32_t payload_offset;
	uint32_t payload_size;
	keemash_ota_v3_stream_t *validator;
	keemash_ota_v3_block_fn visitor;
	void *visitor_context;
	uint32_t block_count;
	esp_err_t error;
} block_context_t;

typedef enum {
	MANIFEST_COUNT_BLOCKS,
	MANIFEST_VALIDATE_BLOCKS,
	MANIFEST_VISIT_BLOCKS,
} manifest_block_mode_t;

static esp_err_t check_manifest_crc(keemash_ota_v3_read_fn read_fn,
	void *read_context, uint32_t manifest_size, uint32_t expected);

static uint32_t le32(const uint8_t *bytes)
{
	return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
		((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static bool count_block(pb_istream_t *stream, const pb_field_t *field,
	void **argument)
{
	(void)field;
	block_context_t *blocks = *argument;
	if (blocks->block_count >= KEEMASH_OTA_V3_MAX_BLOCK_COUNT) {
		blocks->error = ESP_ERR_INVALID_SIZE;
		return false;
	}
	keemash_fabric_v2_FirmwareBlockDescriptor descriptor =
		keemash_fabric_v2_FirmwareBlockDescriptor_init_zero;
	if (!pb_decode(stream, keemash_fabric_v2_FirmwareBlockDescriptor_fields,
		&descriptor)) {
		blocks->error = ESP_ERR_INVALID_RESPONSE;
		return false;
	}
	blocks->block_count++;
	return true;
}

static bool validate_block(pb_istream_t *stream, const pb_field_t *field,
	void **argument)
{
	(void)field;
	block_context_t *blocks = *argument;
	if (blocks->block_count >= KEEMASH_OTA_V3_MAX_BLOCK_COUNT) {
		blocks->error = ESP_ERR_INVALID_SIZE;
		return false;
	}
	keemash_fabric_v2_FirmwareBlockDescriptor descriptor =
		keemash_fabric_v2_FirmwareBlockDescriptor_init_zero;
	if (!pb_decode(stream, keemash_fabric_v2_FirmwareBlockDescriptor_fields,
		&descriptor)) {
		blocks->error = ESP_ERR_INVALID_RESPONSE;
		return false;
	}
	if (descriptor.encoded_offset > blocks->payload_size ||
	    descriptor.encoded_size == 0U ||
	    descriptor.encoded_size >
		blocks->payload_size - descriptor.encoded_offset) {
		blocks->error = ESP_ERR_INVALID_SIZE;
		return false;
	}
	uint8_t chunk[KOTA3_READ_BYTES];
	uint32_t consumed = 0U;
	while (consumed < descriptor.encoded_size) {
		size_t count = descriptor.encoded_size - consumed;
		if (count > sizeof(chunk)) count = sizeof(chunk);
		blocks->error = blocks->read(blocks->payload_offset +
			descriptor.encoded_offset + consumed, chunk, count,
			blocks->context);
		if (blocks->error != ESP_OK) return false;
		blocks->error = keemash_ota_v3_stream_feed(blocks->validator,
			&descriptor, consumed, chunk, count,
			consumed + count == descriptor.encoded_size);
		if (blocks->error != ESP_OK) return false;
		consumed += count;
	}
	blocks->block_count++;
	return true;
}

static bool visit_block(pb_istream_t *stream, const pb_field_t *field,
	void **argument)
{
	(void)field;
	block_context_t *blocks = *argument;
	if (!blocks->visitor ||
	    blocks->block_count >= KEEMASH_OTA_V3_MAX_BLOCK_COUNT) {
		blocks->error = ESP_ERR_INVALID_SIZE;
		return false;
	}
	keemash_fabric_v2_FirmwareBlockDescriptor descriptor =
		keemash_fabric_v2_FirmwareBlockDescriptor_init_zero;
	if (!pb_decode(stream, keemash_fabric_v2_FirmwareBlockDescriptor_fields,
		&descriptor)) {
		blocks->error = ESP_ERR_INVALID_RESPONSE;
		return false;
	}
	if (descriptor.encoded_offset > blocks->payload_size ||
	    descriptor.encoded_size == 0U ||
	    descriptor.encoded_size >
		blocks->payload_size - descriptor.encoded_offset) {
		blocks->error = ESP_ERR_INVALID_SIZE;
		return false;
	}
	blocks->error = blocks->visitor(&descriptor,
		blocks->payload_offset + descriptor.encoded_offset,
		blocks->visitor_context);
	if (blocks->error != ESP_OK) return false;
	blocks->block_count++;
	return true;
}

static esp_err_t decode_manifest(keemash_ota_v3_read_fn read_fn,
	void *read_context, uint32_t manifest_size,
	keemash_fabric_v2_FirmwareArtifactManifest *manifest,
	block_context_t *blocks, manifest_block_mode_t mode)
{
	uint8_t *manifest_bytes = malloc(manifest_size);
	if (!manifest_bytes) return ESP_ERR_NO_MEM;
	esp_err_t err = read_fn(KOTA3_HEADER_SIZE, manifest_bytes,
		manifest_size, read_context);
	if (err != ESP_OK) {
		free(manifest_bytes);
		return err;
	}
	*manifest = (keemash_fabric_v2_FirmwareArtifactManifest)
		keemash_fabric_v2_FirmwareArtifactManifest_init_zero;
	manifest->blocks.funcs.decode = mode == MANIFEST_VALIDATE_BLOCKS ?
		validate_block : mode == MANIFEST_VISIT_BLOCKS ?
		visit_block : count_block;
	manifest->blocks.arg = blocks;
	pb_istream_t input = pb_istream_from_buffer(manifest_bytes,
		manifest_size);
	bool decoded = pb_decode(&input,
		keemash_fabric_v2_FirmwareArtifactManifest_fields, manifest);
	if (!decoded || input.bytes_left != 0U) {
		ESP_LOGW("ota3_package", "manifest decode failed: %s remaining=%lu blocks=%lu err=%s",
			PB_GET_ERROR(&input), (unsigned long)input.bytes_left,
			(unsigned long)blocks->block_count,
			esp_err_to_name(blocks->error));
		err = blocks->error != ESP_OK ? blocks->error :
			ESP_ERR_INVALID_RESPONSE;
	}
	free(manifest_bytes);
	return err;
}

static esp_err_t read_header(keemash_ota_v3_read_fn read_fn,
	void *read_context, uint32_t package_size, uint32_t *manifest_size)
{
	if (!read_fn || !manifest_size || package_size <= KOTA3_HEADER_SIZE ||
	    package_size > KEEMASH_OTA_V3_MAX_PACKAGE_SIZE)
		return ESP_ERR_INVALID_ARG;
	uint8_t header[KOTA3_HEADER_SIZE];
	esp_err_t err = read_fn(0U, header, sizeof(header), read_context);
	if (err != ESP_OK) return err;
	if (memcmp(header, s_magic, sizeof(s_magic)) != 0)
		return ESP_ERR_INVALID_RESPONSE;
	*manifest_size = le32(header + 8U);
	if (*manifest_size == 0U || *manifest_size > KOTA3_MANIFEST_MAX ||
	    *manifest_size > package_size - KOTA3_HEADER_SIZE)
		return ESP_ERR_INVALID_SIZE;
	return check_manifest_crc(read_fn, read_context, *manifest_size,
		le32(header + 12U));
}

esp_err_t keemash_ota_v3_package_inspect(
	keemash_ota_v3_read_fn read_fn, void *read_context,
	uint32_t package_size, keemash_ota_v3_package_info_t *out)
{
	if (!out) return ESP_ERR_INVALID_ARG;
	uint32_t manifest_size = 0U;
	esp_err_t err = read_header(read_fn, read_context, package_size,
		&manifest_size);
	if (err != ESP_OK) return err;
	keemash_fabric_v2_FirmwareArtifactManifest *manifest =
		calloc(1U, sizeof(*manifest));
	if (!manifest) return ESP_ERR_NO_MEM;
	block_context_t blocks = {.error = ESP_OK};
	err = decode_manifest(read_fn, read_context, manifest_size, manifest,
		&blocks, MANIFEST_COUNT_BLOCKS);
	if (err != ESP_OK) goto done;
	keemash_ota_v3_package_info_t info = {
		.manifest_size = manifest_size,
		.payload_offset = KOTA3_HEADER_SIZE + manifest_size,
		.package_size = package_size,
	};
	if (manifest->signed_fields.size > sizeof(info.signed_fields) ||
	    manifest->signature.size != sizeof(info.signature)) {
		err = ESP_ERR_INVALID_SIZE;
		goto done;
	}
	info.signed_fields_len = manifest->signed_fields.size;
	info.signature_len = manifest->signature.size;
	memcpy(info.signed_fields, manifest->signed_fields.bytes,
		info.signed_fields_len);
	memcpy(info.signature, manifest->signature.bytes,
		info.signature_len);
	err = keemash_ota_v3_verify_signed_fields(info.signed_fields,
		info.signed_fields_len, info.signature, info.signature_len,
		&info.fields);
	if (err != ESP_OK) goto done;
	if (info.fields.block_count != blocks.block_count ||
	    info.fields.encoded_size != package_size - info.payload_offset ||
	    info.fields.has_base_image) {
		err = ESP_ERR_INVALID_SIZE;
		goto done;
	}
	*out = info;
done:
	free(manifest);
	return err;
}

esp_err_t keemash_ota_v3_package_for_each_block(
	keemash_ota_v3_read_fn read_fn, void *read_context,
	const keemash_ota_v3_package_info_t *package,
	keemash_ota_v3_block_fn block_fn, void *block_context)
{
	if (!read_fn || !package || !block_fn ||
	    package->manifest_size == 0U ||
	    package->payload_offset != KOTA3_HEADER_SIZE + package->manifest_size ||
	    package->package_size < package->payload_offset ||
	    package->fields.encoded_size !=
		package->package_size - package->payload_offset)
		return ESP_ERR_INVALID_ARG;
	keemash_fabric_v2_FirmwareArtifactManifest *manifest =
		calloc(1U, sizeof(*manifest));
	if (!manifest) return ESP_ERR_NO_MEM;
	block_context_t blocks = {
		.payload_offset = package->payload_offset,
		.payload_size = package->fields.encoded_size,
		.visitor = block_fn,
		.visitor_context = block_context,
		.error = ESP_OK,
	};
	esp_err_t err = decode_manifest(read_fn, read_context,
		package->manifest_size, manifest, &blocks, MANIFEST_VISIT_BLOCKS);
	if (err == ESP_OK && blocks.block_count != package->fields.block_count)
		err = ESP_ERR_INVALID_RESPONSE;
	free(manifest);
	return err;
}

static esp_err_t discard_output(const uint8_t *bytes, size_t length,
	void *context)
{
	(void)bytes;
	(void)length;
	(void)context;
	return ESP_OK;
}

static esp_err_t check_manifest_crc(keemash_ota_v3_read_fn read_fn,
	void *read_context, uint32_t manifest_size, uint32_t expected)
{
	uint8_t buffer[KOTA3_READ_BYTES];
	uLong crc = crc32(0L, Z_NULL, 0);
	uint32_t offset = KOTA3_HEADER_SIZE;
	uint32_t remaining = manifest_size;
	while (remaining > 0U) {
		size_t count = remaining < sizeof(buffer) ? remaining :
			sizeof(buffer);
		esp_err_t err = read_fn(offset, buffer, count, read_context);
		if (err != ESP_OK) return err;
		crc = crc32(crc, buffer, count);
		offset += count;
		remaining -= count;
	}
	return (uint32_t)crc == expected ? ESP_OK : ESP_ERR_INVALID_CRC;
}

esp_err_t keemash_ota_v3_verify_package(
	keemash_ota_v3_read_fn read_fn, void *read_context,
	uint32_t package_size, keemash_ota_v3_signed_fields_t *out)
{
	if (!out) return ESP_ERR_INVALID_ARG;
	uint32_t manifest_size = 0U;
	esp_err_t err = read_header(read_fn, read_context, package_size,
		&manifest_size);
	if (err != ESP_OK) return err;

	keemash_fabric_v2_FirmwareArtifactManifest *manifest =
		calloc(1U, sizeof(*manifest));
	keemash_ota_v3_stream_t *validator = calloc(1U, sizeof(*validator));
	if (!manifest || !validator) {
		free(manifest);
		free(validator);
		return ESP_ERR_NO_MEM;
	}
	block_context_t blocks = {.error = ESP_OK};
	err = decode_manifest(read_fn, read_context, manifest_size,
		manifest, &blocks, MANIFEST_COUNT_BLOCKS);
	if (err != ESP_OK) goto done;
	uint32_t expected_count = blocks.block_count;
	uint8_t original_signed_fields[1024];
	uint8_t original_signature[KEEMASH_OTA_V3_SIGNATURE_LEN];
	size_t original_signed_size = manifest->signed_fields.size;
	size_t original_signature_size = manifest->signature.size;
	memcpy(original_signed_fields, manifest->signed_fields.bytes,
		original_signed_size);
	memcpy(original_signature, manifest->signature.bytes,
		original_signature_size);
	keemash_ota_v3_signed_fields_t fields;
	err = keemash_ota_v3_verify_signed_fields(
		manifest->signed_fields.bytes, manifest->signed_fields.size,
		manifest->signature.bytes, manifest->signature.size, &fields);
	if (err != ESP_OK) goto done;
	uint32_t payload_offset = KOTA3_HEADER_SIZE + manifest_size;
	if (fields.block_count != expected_count ||
	    fields.encoded_size != package_size - payload_offset ||
	    fields.has_base_image) {
		err = ESP_ERR_INVALID_SIZE;
		goto done;
	}
	err = keemash_ota_v3_stream_begin(validator, &fields,
		discard_output, NULL);
	if (err != ESP_OK) goto done;
	blocks = (block_context_t){
		.read = read_fn,
		.context = read_context,
		.payload_offset = payload_offset,
		.payload_size = fields.encoded_size,
		.validator = validator,
		.error = ESP_OK,
	};
	err = decode_manifest(read_fn, read_context, manifest_size,
		manifest, &blocks, MANIFEST_VALIDATE_BLOCKS);
	if (err == ESP_OK &&
	    (manifest->signed_fields.size != original_signed_size ||
	     manifest->signature.size != original_signature_size ||
	     memcmp(manifest->signed_fields.bytes, original_signed_fields,
		original_signed_size) != 0 ||
	     memcmp(manifest->signature.bytes, original_signature,
		original_signature_size) != 0))
		err = ESP_ERR_INVALID_CRC;
	if (err == ESP_OK && blocks.block_count != expected_count)
		err = ESP_ERR_INVALID_RESPONSE;
	if (err == ESP_OK)
		err = keemash_ota_v3_stream_finish(validator);
	if (err == ESP_OK) *out = fields;
done:
	keemash_ota_v3_stream_end(validator);
	free(validator);
	free(manifest);
	return err;
}
