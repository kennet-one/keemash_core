// SPDX-License-Identifier: GPL-2.0-only

#include "keemash_ota_v3.h"

#include <string.h>

#include "sdkconfig.h"
#include "mbedtls/md.h"
#include "pb_decode.h"
#include "pb_encode.h"
#include "psa/crypto.h"

#if CONFIG_KEEMASH_OTA_V3_ENABLE
static int hex_nibble(char value)
{
	if (value >= '0' && value <= '9') return value - '0';
	if (value >= 'a' && value <= 'f') return value - 'a' + 10;
	if (value >= 'A' && value <= 'F') return value - 'A' + 10;
	return -1;
}
#endif

static esp_err_t decode_public_key(uint8_t out[KEEMASH_OTA_V3_PUBLIC_KEY_LEN])
{
#if CONFIG_KEEMASH_OTA_V3_ENABLE
	const char *hex = CONFIG_KEEMASH_OTA_V3_TRUSTED_P256_PUBKEY_HEX;
	if (!hex || strlen(hex) != KEEMASH_OTA_V3_PUBLIC_KEY_LEN * 2U) {
		return ESP_ERR_INVALID_SIZE;
	}
	for (size_t i = 0; i < KEEMASH_OTA_V3_PUBLIC_KEY_LEN; ++i) {
		int high = hex_nibble(hex[i * 2U]);
		int low = hex_nibble(hex[i * 2U + 1U]);
		if (high < 0 || low < 0) return ESP_ERR_INVALID_ARG;
		out[i] = (uint8_t)((high << 4) | low);
	}
	return out[0] == 0x04U ? ESP_OK : ESP_ERR_INVALID_ARG;
#else
	(void)out;
	return ESP_ERR_NOT_SUPPORTED;
#endif
}

static bool copy_hash(const pb_bytes_array_t *source, uint8_t out[32], bool optional)
{
	if (!source || (!optional && source->size != 32U) ||
	    (optional && source->size != 0U && source->size != 32U)) {
		return false;
	}
	memset(out, 0, 32);
	if (source->size == 32U) memcpy(out, source->bytes, 32);
	return true;
}

static esp_err_t verify_p256(const uint8_t *data, size_t data_len,
			     const uint8_t signature[64])
{
	uint8_t public_key[KEEMASH_OTA_V3_PUBLIC_KEY_LEN];
	esp_err_t err = decode_public_key(public_key);
	if (err != ESP_OK) return err;

	uint8_t digest[32];
	const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (!info || mbedtls_md(info, data, data_len, digest) != 0) return ESP_FAIL;

	psa_status_t status = psa_crypto_init();
	if (status != PSA_SUCCESS) return ESP_FAIL;
	psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_HASH);
	psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_set_key_type(&attributes,
		PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&attributes, 256);
	psa_key_id_t key = 0;
	status = psa_import_key(&attributes, public_key, sizeof(public_key), &key);
	psa_reset_key_attributes(&attributes);
	if (status != PSA_SUCCESS) return ESP_ERR_INVALID_ARG;
	status = psa_verify_hash(key, PSA_ALG_ECDSA(PSA_ALG_SHA_256),
			 digest, sizeof(digest), signature, 64);
	(void)psa_destroy_key(key);
	return status == PSA_SUCCESS ? ESP_OK : ESP_ERR_INVALID_CRC;
}

esp_err_t keemash_ota_v3_verify_signed_fields(
	const uint8_t *signed_fields, size_t signed_fields_len,
	const uint8_t *signature, size_t signature_len,
	keemash_ota_v3_signed_fields_t *out)
{
	if (!signed_fields || signed_fields_len == 0U || !signature || !out) {
		return ESP_ERR_INVALID_ARG;
	}
	if (signed_fields_len > 1024U) return ESP_ERR_INVALID_SIZE;
	if (signature_len != KEEMASH_OTA_V3_SIGNATURE_LEN) {
		return ESP_ERR_INVALID_SIZE;
	}
	esp_err_t err = verify_p256(signed_fields, signed_fields_len, signature);
	if (err != ESP_OK) return err;

	keemash_fabric_v2_FirmwareArtifactSignedFields fields =
		keemash_fabric_v2_FirmwareArtifactSignedFields_init_zero;
	pb_istream_t stream = pb_istream_from_buffer(signed_fields, signed_fields_len);
	if (!pb_decode(&stream,
		       keemash_fabric_v2_FirmwareArtifactSignedFields_fields,
		       &fields)) {
		return ESP_ERR_INVALID_RESPONSE;
	}
	if (fields.schema_version != KEEMASH_OTA_V3_SCHEMA_VERSION ||
	    fields.raw_size == 0U ||
	    fields.required_app_slot_size < fields.raw_size ||
	    fields.raw_size > KEEMASH_OTA_V3_MAX_IMAGE_SIZE ||
	    fields.encoded_size > KEEMASH_OTA_V3_MAX_PACKAGE_SIZE ||
	    fields.block_count == 0U ||
	    fields.block_count > KEEMASH_OTA_V3_MAX_BLOCK_COUNT ||
	    fields.deflate_window_bits != KEEMASH_OTA_V3_DEFLATE_WINDOW_BITS ||
	    fields.project_name[0] == '\0' || fields.chip_target[0] == '\0' ||
	    fields.signing_key_id[0] == '\0') {
		return ESP_ERR_INVALID_ARG;
	}
	if (fields.codec != keemash_fabric_v2_FirmwareArtifactCodec_ARTIFACT_CODEC_FULL_DEFLATE
#if CONFIG_KEEMASH_OTA_V3_DELTA_EXPERIMENTAL
	    && fields.codec != keemash_fabric_v2_FirmwareArtifactCodec_ARTIFACT_CODEC_DELTA_BLOCK
#endif
	) {
		return ESP_ERR_NOT_SUPPORTED;
	}
	if ((fields.codec == keemash_fabric_v2_FirmwareArtifactCodec_ARTIFACT_CODEC_FULL_DEFLATE &&
	     (fields.block_size != KEEMASH_OTA_V3_FULL_BLOCK_SIZE ||
	      fields.encoded_size == 0U || fields.base_image_sha256.size != 0U)) ||
	    (fields.codec == keemash_fabric_v2_FirmwareArtifactCodec_ARTIFACT_CODEC_DELTA_BLOCK &&
	     (fields.block_size != KEEMASH_OTA_V3_DELTA_BLOCK_SIZE ||
	      fields.base_image_sha256.size != 32U))) {
		return ESP_ERR_INVALID_ARG;
	}
	if (fields.block_count !=
	    (fields.raw_size + fields.block_size - 1U) / fields.block_size) {
		return ESP_ERR_INVALID_ARG;
	}
	memset(out, 0, sizeof(*out));
	if (!copy_hash((const pb_bytes_array_t *)&fields.image_sha256,
		       out->image_sha256, false) ||
	    !copy_hash((const pb_bytes_array_t *)&fields.encoded_sha256,
		       out->encoded_sha256, false) ||
	    !copy_hash((const pb_bytes_array_t *)&fields.block_table_sha256,
		       out->block_table_sha256, false) ||
	    !copy_hash((const pb_bytes_array_t *)&fields.base_image_sha256,
		       out->base_image_sha256, true)) {
		return ESP_ERR_INVALID_SIZE;
	}
	out->schema_version = fields.schema_version;
	strncpy(out->project_name, fields.project_name, sizeof(out->project_name) - 1U);
	strncpy(out->chip_target, fields.chip_target, sizeof(out->chip_target) - 1U);
	strncpy(out->firmware_version, fields.firmware_version,
		sizeof(out->firmware_version) - 1U);
	strncpy(out->build_commit, fields.build_commit, sizeof(out->build_commit) - 1U);
	strncpy(out->signing_key_id, fields.signing_key_id,
		sizeof(out->signing_key_id) - 1U);
	out->minimum_core_version = fields.minimum_core_version;
	out->minimum_fabric_schema = fields.minimum_fabric_schema;
	out->raw_size = fields.raw_size;
	out->encoded_size = fields.encoded_size;
	out->required_app_slot_size = fields.required_app_slot_size;
	out->codec = (uint32_t)fields.codec;
	out->block_size = fields.block_size;
	out->block_count = fields.block_count;
	out->deflate_window_bits = fields.deflate_window_bits;
	out->has_base_image = fields.base_image_sha256.size == 32U;
	return ESP_OK;
}

esp_err_t keemash_ota_v3_check_target(
	const keemash_ota_v3_signed_fields_t *fields,
	const char *project_name, const char *chip_target,
	uint32_t app_slot_size, uint32_t core_version,
	uint32_t fabric_schema)
{
	if (!fields || !project_name || !chip_target) return ESP_ERR_INVALID_ARG;
	if (strcmp(fields->project_name, project_name) != 0 ||
	    strcmp(fields->chip_target, chip_target) != 0) return ESP_ERR_INVALID_ARG;
	if (fields->raw_size > app_slot_size ||
	    fields->required_app_slot_size > app_slot_size) return ESP_ERR_INVALID_SIZE;
	if (fields->minimum_core_version > core_version ||
	    fields->minimum_fabric_schema > fabric_schema) return ESP_ERR_NOT_SUPPORTED;
	return ESP_OK;
}

esp_err_t keemash_ota_v3_encode_transfer(
	const keemash_fabric_v2_OtaTransfer *message,
	uint8_t *out, size_t capacity, size_t *written)
{
	if (!message || !out || !written || capacity == 0U) return ESP_ERR_INVALID_ARG;
	pb_ostream_t stream = pb_ostream_from_buffer(out, capacity);
	if (!pb_encode(&stream, keemash_fabric_v2_OtaTransfer_fields, message)) {
		return stream.bytes_written >= capacity ? ESP_ERR_INVALID_SIZE : ESP_FAIL;
	}
	*written = stream.bytes_written;
	return ESP_OK;
}

esp_err_t keemash_ota_v3_decode_transfer(
	const uint8_t *data, size_t length,
	keemash_fabric_v2_OtaTransfer *message)
{
	if (!data || length == 0U || !message ||
	    length > keemash_fabric_v2_OtaTransfer_size) {
		return ESP_ERR_INVALID_ARG;
	}
	*message = (keemash_fabric_v2_OtaTransfer)
		keemash_fabric_v2_OtaTransfer_init_zero;
	pb_istream_t stream = pb_istream_from_buffer(data, length);
	return pb_decode(&stream, keemash_fabric_v2_OtaTransfer_fields, message)
		? ESP_OK : ESP_ERR_INVALID_RESPONSE;
}

esp_err_t keemash_ota_v3_encode_mesh_message(
	const keemash_fabric_v2_OtaMeshMessage *message,
	uint8_t *out, size_t capacity, size_t *written)
{
	if (!message || !out || !written || capacity == 0U)
		return ESP_ERR_INVALID_ARG;
	pb_ostream_t stream = pb_ostream_from_buffer(out, capacity);
	if (!pb_encode(&stream, keemash_fabric_v2_OtaMeshMessage_fields,
		       message)) {
		return stream.bytes_written >= capacity ? ESP_ERR_INVALID_SIZE :
			ESP_FAIL;
	}
	*written = stream.bytes_written;
	return ESP_OK;
}

esp_err_t keemash_ota_v3_decode_mesh_message(
	const uint8_t *data, size_t length,
	keemash_fabric_v2_OtaMeshMessage *message)
{
	if (!data || length == 0U || !message ||
	    length > keemash_fabric_v2_OtaMeshMessage_size)
		return ESP_ERR_INVALID_ARG;
	*message = (keemash_fabric_v2_OtaMeshMessage)
		keemash_fabric_v2_OtaMeshMessage_init_zero;
	pb_istream_t stream = pb_istream_from_buffer(data, length);
	return pb_decode(&stream, keemash_fabric_v2_OtaMeshMessage_fields,
		message) ? ESP_OK : ESP_ERR_INVALID_RESPONSE;
}

static size_t encode_varint(uint64_t value, uint8_t out[10])
{
	size_t count = 0;
	do {
		uint8_t byte = (uint8_t)(value & 0x7fU);
		value >>= 7;
		if (value != 0U) byte |= 0x80U;
		out[count++] = byte;
	} while (value != 0U && count < 10U);
	return count;
}

esp_err_t keemash_ota_v3_encode_block_descriptor(
	const keemash_fabric_v2_FirmwareBlockDescriptor *descriptor,
	uint8_t *out, size_t capacity, size_t *written,
	bool length_delimited)
{
	if (!descriptor || !out || !written) return ESP_ERR_INVALID_ARG;
	uint8_t encoded[keemash_fabric_v2_FirmwareBlockDescriptor_size];
	pb_ostream_t stream = pb_ostream_from_buffer(encoded, sizeof(encoded));
	if (!pb_encode(&stream, keemash_fabric_v2_FirmwareBlockDescriptor_fields,
		       descriptor)) {
		return ESP_FAIL;
	}
	uint8_t prefix[10];
	size_t prefix_len = length_delimited ? encode_varint(stream.bytes_written, prefix) : 0U;
	if (capacity < prefix_len + stream.bytes_written) return ESP_ERR_INVALID_SIZE;
	if (prefix_len) memcpy(out, prefix, prefix_len);
	memcpy(out + prefix_len, encoded, stream.bytes_written);
	*written = prefix_len + stream.bytes_written;
	return ESP_OK;
}

esp_err_t keemash_ota_v3_check_block_descriptor(
	const keemash_ota_v3_signed_fields_t *fields,
	const keemash_fabric_v2_FirmwareBlockDescriptor *descriptor,
	uint32_t expected_index, uint32_t expected_raw_offset,
	uint32_t expected_encoded_offset,
	const uint8_t previous_chain[KEEMASH_OTA_V3_SHA256_LEN],
	uint8_t next_chain[KEEMASH_OTA_V3_SHA256_LEN])
{
	if (!fields || !descriptor || !previous_chain || !next_chain ||
	    expected_index >= fields->block_count ||
	    descriptor->index != expected_index ||
	    descriptor->raw_offset != expected_raw_offset ||
	    descriptor->encoded_offset != expected_encoded_offset ||
	    descriptor->raw_size == 0U ||
	    descriptor->raw_size > fields->block_size ||
	    (expected_index + 1U < fields->block_count &&
	     descriptor->raw_size != fields->block_size) ||
	    expected_raw_offset > fields->raw_size ||
	    descriptor->raw_size > fields->raw_size - expected_raw_offset ||
	    expected_encoded_offset > fields->encoded_size ||
	    descriptor->encoded_size > fields->encoded_size - expected_encoded_offset ||
	    descriptor->raw_sha256.size != 32U ||
	    descriptor->encoded_sha256.size != 32U) {
		return ESP_ERR_INVALID_ARG;
	}
	if (descriptor->kind == keemash_fabric_v2_FirmwareBlockKind_FIRMWARE_BLOCK_DEFLATE) {
		if (descriptor->encoded_size == 0U) return ESP_ERR_INVALID_SIZE;
	} else if (descriptor->kind ==
		   keemash_fabric_v2_FirmwareBlockKind_FIRMWARE_BLOCK_COPY_BASE) {
#if CONFIG_KEEMASH_OTA_V3_DELTA_EXPERIMENTAL
		if (fields->codec !=
		    keemash_fabric_v2_FirmwareArtifactCodec_ARTIFACT_CODEC_DELTA_BLOCK ||
		    descriptor->encoded_size != 0U) return ESP_ERR_INVALID_ARG;
#else
		return ESP_ERR_NOT_SUPPORTED;
#endif
	} else {
		return ESP_ERR_NOT_SUPPORTED;
	}
	uint8_t chained[32U + 10U + keemash_fabric_v2_FirmwareBlockDescriptor_size];
	memcpy(chained, previous_chain, 32U);
	size_t encoded_len = 0;
	esp_err_t err = keemash_ota_v3_encode_block_descriptor(
		descriptor, chained + 32U, sizeof(chained) - 32U,
		&encoded_len, true);
	if (err != ESP_OK) return err;
	const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	if (!info || mbedtls_md(info, chained, 32U + encoded_len, next_chain) != 0) {
		return ESP_FAIL;
	}
	if (expected_index + 1U == fields->block_count &&
	    (expected_raw_offset + descriptor->raw_size != fields->raw_size ||
	     expected_encoded_offset + descriptor->encoded_size != fields->encoded_size ||
	     memcmp(next_chain, fields->block_table_sha256, 32U) != 0)) {
		return ESP_ERR_INVALID_CRC;
	}
	return ESP_OK;
}
