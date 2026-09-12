// SPDX-License-Identifier: GPL-2.0-only

#include "keemash_fabric.h"

#include <string.h>

#include "mbedtls/md.h"
#include "pb_decode.h"
#include "pb_encode.h"

static const uint8_t s_legacy_namespace[16] = {
	0x1d, 0x79, 0x70, 0x79, 0x45, 0xa7, 0x57, 0xf5,
	0xa5, 0x91, 0x31, 0x94, 0x3c, 0x7a, 0x68, 0x5c,
};
static const uint8_t s_wire_prefix[KEEMASH_FABRIC_WIRE_PREFIX_SIZE] = {
	'K', 'L', 'F', '2',
};

static uint64_t load_be64(const uint8_t *value)
{
	uint64_t result = 0;
	for (size_t i = 0; i < 8; ++i) result = (result << 8) | value[i];
	return result;
}

static void store_be64(uint64_t value, uint8_t *out)
{
	for (size_t i = 0; i < 8; ++i) {
		out[7 - i] = (uint8_t)value;
		value >>= 8;
	}
}

esp_err_t keemash_fabric_encode(const keemash_fabric_envelope_t *message,
				uint8_t *out, size_t capacity, size_t *written)
{
	if (!message || !out || !written || capacity == 0 ||
	    capacity > KEEMASH_FABRIC_MAX_FRAME) return ESP_ERR_INVALID_ARG;
	esp_err_t valid = keemash_fabric_validate(message, false);
	if (valid != ESP_OK) return valid;
	pb_ostream_t stream = pb_ostream_from_buffer(out, capacity);
	if (!pb_encode(&stream, keemash_fabric_v2_Envelope_fields, message)) {
		return stream.bytes_written >= capacity ? ESP_ERR_INVALID_SIZE : ESP_FAIL;
	}
	*written = stream.bytes_written;
	return ESP_OK;
}

esp_err_t keemash_fabric_decode(const uint8_t *data, size_t length,
				keemash_fabric_envelope_t *message)
{
	if (!data || !message || length == 0 || length > KEEMASH_FABRIC_MAX_FRAME) {
		return ESP_ERR_INVALID_ARG;
	}
	*message = (keemash_fabric_envelope_t)keemash_fabric_v2_Envelope_init_zero;
	pb_istream_t stream = pb_istream_from_buffer(data, length);
	if (!pb_decode(&stream, keemash_fabric_v2_Envelope_fields, message)) {
		return ESP_ERR_INVALID_RESPONSE;
	}
	return keemash_fabric_validate(message, false);
}

bool keemash_fabric_is_wire_frame(const uint8_t *data, size_t length)
{
	return data && length >= KEEMASH_FABRIC_WIRE_PREFIX_SIZE &&
		memcmp(data, s_wire_prefix, sizeof(s_wire_prefix)) == 0;
}

esp_err_t keemash_fabric_encode_wire(const keemash_fabric_envelope_t *message,
				     uint8_t *out, size_t capacity,
				     size_t *written)
{
	if (!message || !out || !written ||
	    capacity < KEEMASH_FABRIC_WIRE_PREFIX_SIZE ||
	    capacity > KEEMASH_FABRIC_MAX_WIRE_FRAME) {
		return ESP_ERR_INVALID_ARG;
	}
	memcpy(out, s_wire_prefix, sizeof(s_wire_prefix));
	size_t payload_len = 0;
	esp_err_t err = keemash_fabric_encode(message,
		out + KEEMASH_FABRIC_WIRE_PREFIX_SIZE,
		capacity - KEEMASH_FABRIC_WIRE_PREFIX_SIZE, &payload_len);
	if (err != ESP_OK) return err;
	*written = KEEMASH_FABRIC_WIRE_PREFIX_SIZE + payload_len;
	return ESP_OK;
}

esp_err_t keemash_fabric_decode_wire(const uint8_t *data, size_t length,
				     keemash_fabric_envelope_t *message)
{
	if (!keemash_fabric_is_wire_frame(data, length) ||
	    length == KEEMASH_FABRIC_WIRE_PREFIX_SIZE ||
	    length > KEEMASH_FABRIC_MAX_WIRE_FRAME) {
		return ESP_ERR_INVALID_ARG;
	}
	return keemash_fabric_decode(data + KEEMASH_FABRIC_WIRE_PREFIX_SIZE,
		length - KEEMASH_FABRIC_WIRE_PREFIX_SIZE, message);
}

esp_err_t keemash_fabric_validate(const keemash_fabric_envelope_t *message,
				  bool allow_zero_rtt)
{
	if (!message || message->protocol_version != KEEMASH_FABRIC_VERSION ||
	    message->traffic_class <= keemash_fabric_v2_TrafficClass_TRAFFIC_UNSPECIFIED ||
	    message->traffic_class > keemash_fabric_v2_TrafficClass_TRAFFIC_OTA ||
	    message->delivery <= keemash_fabric_v2_DeliveryMode_DELIVERY_UNSPECIFIED ||
	    message->delivery > keemash_fabric_v2_DeliveryMode_DELIVERY_SNAPSHOT ||
	    message->which_body < keemash_fabric_v2_Envelope_hello_tag ||
	    message->which_body > keemash_fabric_v2_Envelope_probe_tag) {
		return ESP_ERR_INVALID_ARG;
	}
	if (message->which_body == keemash_fabric_v2_Envelope_hello_tag &&
	    message->body.hello.zero_rtt && !allow_zero_rtt) {
		return ESP_ERR_NOT_SUPPORTED;
	}
	if (message->traffic_class == keemash_fabric_v2_TrafficClass_TRAFFIC_CONTROL &&
	    message->which_body == keemash_fabric_v2_Envelope_control_request_tag &&
	    (!message->body.control_request.has_operation_id ||
	     keemash_fabric_id_is_zero(&message->body.control_request.operation_id))) {
		return ESP_ERR_INVALID_ARG;
	}
	return ESP_OK;
}

bool keemash_fabric_id_is_zero(const keemash_fabric_id_t *id)
{
	return !id || (id->high == 0 && id->low == 0);
}

void keemash_fabric_id_to_bytes(const keemash_fabric_id_t *id, uint8_t out[16])
{
	if (!out) return;
	if (!id) {
		memset(out, 0, 16);
		return;
	}
	store_be64(id->high, out);
	store_be64(id->low, out + 8);
}

void keemash_fabric_id_from_bytes(const uint8_t bytes[16], keemash_fabric_id_t *id)
{
	if (!bytes || !id) return;
	id->high = load_be64(bytes);
	id->low = load_be64(bytes + 8);
}

esp_err_t keemash_fabric_uuid_v5(const keemash_fabric_id_t *namespace_id,
				 const void *name, size_t name_len,
				 keemash_fabric_id_t *out)
{
	if (!namespace_id || (!name && name_len) || !out) return ESP_ERR_INVALID_ARG;
	const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
	if (!info) return ESP_ERR_NOT_SUPPORTED;
	mbedtls_md_context_t ctx;
	mbedtls_md_init(&ctx);
	uint8_t namespace_bytes[16];
	uint8_t digest[20];
	keemash_fabric_id_to_bytes(namespace_id, namespace_bytes);
	int rc = mbedtls_md_setup(&ctx, info, 0);
	if (rc == 0) rc = mbedtls_md_starts(&ctx);
	if (rc == 0) rc = mbedtls_md_update(&ctx, namespace_bytes, sizeof(namespace_bytes));
	if (rc == 0 && name_len) rc = mbedtls_md_update(&ctx, name, name_len);
	if (rc == 0) rc = mbedtls_md_finish(&ctx, digest);
	mbedtls_md_free(&ctx);
	if (rc != 0) return ESP_FAIL;
	digest[6] = (uint8_t)((digest[6] & 0x0fU) | 0x50U);
	digest[8] = (uint8_t)((digest[8] & 0x3fU) | 0x80U);
	keemash_fabric_id_from_bytes(digest, out);
	return ESP_OK;
}

esp_err_t keemash_fabric_legacy_node_id(const uint8_t root_mac[6],
					const uint8_t node_mac[6],
					keemash_fabric_id_t *out)
{
	if (!root_mac || !node_mac || !out) return ESP_ERR_INVALID_ARG;
	keemash_fabric_id_t namespace_id;
	keemash_fabric_id_from_bytes(s_legacy_namespace, &namespace_id);
	uint8_t name[12];
	memcpy(name, root_mac, 6);
	memcpy(name + 6, node_mac, 6);
	return keemash_fabric_uuid_v5(&namespace_id, name, sizeof(name), out);
}

esp_err_t keemash_fabric_endpoint_id(const keemash_fabric_id_t *node_id,
				     const char *path,
				     keemash_fabric_id_t *out)
{
	if (!node_id || !path || !path[0] || strlen(path) > 96 || !out) {
		return ESP_ERR_INVALID_ARG;
	}
	return keemash_fabric_uuid_v5(node_id, path, strlen(path), out);
}

bool keemash_fabric_sequence_after(uint64_t candidate, uint64_t reference)
{
	return candidate != reference && (int64_t)(candidate - reference) > 0;
}
