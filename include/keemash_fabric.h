// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "keelink-fabric-v2.pb.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KEEMASH_FABRIC_VERSION 2U
#define KEEMASH_FABRIC_MAX_FRAME 4096U
#define KEEMASH_FABRIC_WIRE_PREFIX_SIZE 4U
#define KEEMASH_FABRIC_MAX_WIRE_FRAME \
	(KEEMASH_FABRIC_WIRE_PREFIX_SIZE + KEEMASH_FABRIC_MAX_FRAME)
#define KEEMASH_FABRIC_CAP_TYPED_GRAPH (1ULL << 0)
#define KEEMASH_FABRIC_CAP_RESUME (1ULL << 1)
#define KEEMASH_FABRIC_CAP_OPERATION_ID (1ULL << 2)
#define KEEMASH_FABRIC_CAP_LATEST_SENSOR (1ULL << 3)
#define KEEMASH_FABRIC_CAP_QUIC_RESERVED (1ULL << 4)

typedef keemash_fabric_v2_Id128 keemash_fabric_id_t;
typedef keemash_fabric_v2_Envelope keemash_fabric_envelope_t;

esp_err_t keemash_fabric_encode(const keemash_fabric_envelope_t *message,
				uint8_t *out, size_t capacity, size_t *written);
esp_err_t keemash_fabric_decode(const uint8_t *data, size_t length,
				keemash_fabric_envelope_t *message);
esp_err_t keemash_fabric_encode_wire(const keemash_fabric_envelope_t *message,
				     uint8_t *out, size_t capacity,
				     size_t *written);
esp_err_t keemash_fabric_decode_wire(const uint8_t *data, size_t length,
				     keemash_fabric_envelope_t *message);
bool keemash_fabric_is_wire_frame(const uint8_t *data, size_t length);
esp_err_t keemash_fabric_validate(const keemash_fabric_envelope_t *message,
				  bool allow_zero_rtt);

bool keemash_fabric_id_is_zero(const keemash_fabric_id_t *id);
void keemash_fabric_id_to_bytes(const keemash_fabric_id_t *id, uint8_t out[16]);
void keemash_fabric_id_from_bytes(const uint8_t bytes[16], keemash_fabric_id_t *id);
esp_err_t keemash_fabric_uuid_v5(const keemash_fabric_id_t *namespace_id,
				 const void *name, size_t name_len,
				 keemash_fabric_id_t *out);
esp_err_t keemash_fabric_legacy_node_id(const uint8_t root_mac[6],
					const uint8_t node_mac[6],
					keemash_fabric_id_t *out);
esp_err_t keemash_fabric_endpoint_id(const keemash_fabric_id_t *node_id,
				     const char *path,
				     keemash_fabric_id_t *out);

bool keemash_fabric_sequence_after(uint64_t candidate, uint64_t reference);

#ifdef __cplusplus
}
#endif
