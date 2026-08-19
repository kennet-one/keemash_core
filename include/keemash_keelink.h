// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KEEMASH_KEELINK_VERSION 1U
#define KEEMASH_KEELINK_HEADER_SIZE 32U
#define KEEMASH_KEELINK_TLV_HEADER_SIZE 6U
#define KEEMASH_KEELINK_MAX_PAYLOAD 4096U

typedef enum {
	KEEMASH_KEELINK_HELLO = 1,
	KEEMASH_KEELINK_WELCOME = 2,
	KEEMASH_KEELINK_REQUEST = 3,
	KEEMASH_KEELINK_RESPONSE = 4,
	KEEMASH_KEELINK_EVENT = 5,
	KEEMASH_KEELINK_SNAPSHOT = 6,
	KEEMASH_KEELINK_GAP = 7,
	KEEMASH_KEELINK_HEARTBEAT = 8,
	KEEMASH_KEELINK_ERROR = 9,
} keemash_keelink_kind_t;

typedef enum {
	KEEMASH_KEELINK_CH_SYSTEM = 1,
	KEEMASH_KEELINK_CH_INVENTORY = 2,
	KEEMASH_KEELINK_CH_CONTROL = 3,
	KEEMASH_KEELINK_CH_STATE = 4,
	KEEMASH_KEELINK_CH_SENSOR = 5,
	KEEMASH_KEELINK_CH_TOPOLOGY = 6,
	KEEMASH_KEELINK_CH_TASK = 7,
	KEEMASH_KEELINK_CH_MEMORY = 8,
	KEEMASH_KEELINK_CH_LOG = 9,
	KEEMASH_KEELINK_CH_OTA_STATUS = 10,
	KEEMASH_KEELINK_CH_BUILDER_RESERVED = 32,
	KEEMASH_KEELINK_CH_AUDIO_CONTROL_RESERVED = 33,
} keemash_keelink_channel_t;

typedef enum {
	KEEMASH_KEELINK_TLV_U32 = 1,
	KEEMASH_KEELINK_TLV_U64 = 2,
	KEEMASH_KEELINK_TLV_I32 = 3,
	KEEMASH_KEELINK_TLV_BOOL = 4,
	KEEMASH_KEELINK_TLV_BYTES = 5,
	KEEMASH_KEELINK_TLV_UTF8 = 6,
} keemash_keelink_tlv_type_t;

typedef struct {
	uint8_t kind;
	uint16_t flags;
	uint16_t channel;
	uint32_t payload_len;
	uint64_t session_id;
	uint32_t message_id;
	uint32_t correlation_id;
} keemash_keelink_header_t;

typedef struct {
	uint8_t *buffer;
	size_t capacity;
	size_t length;
} keemash_keelink_writer_t;

typedef struct {
	const uint8_t *buffer;
	size_t length;
	size_t offset;
} keemash_keelink_reader_t;

typedef struct {
	uint16_t field_id;
	uint8_t type;
	uint8_t flags;
	const uint8_t *data;
	uint16_t length;
} keemash_keelink_tlv_t;

esp_err_t keemash_keelink_encode_header(uint8_t out[KEEMASH_KEELINK_HEADER_SIZE],
					const keemash_keelink_header_t *header);
esp_err_t keemash_keelink_decode_header(const void *frame, size_t frame_len,
					keemash_keelink_header_t *header);
size_t keemash_keelink_frame_size(const keemash_keelink_header_t *header);
void keemash_keelink_writer_init(keemash_keelink_writer_t *writer,
				  void *buffer, size_t capacity);
esp_err_t keemash_keelink_put(keemash_keelink_writer_t *writer,
			      uint16_t field_id, uint8_t type, uint8_t flags,
			      const void *data, size_t length);
esp_err_t keemash_keelink_put_u32(keemash_keelink_writer_t *writer,
				  uint16_t field_id, uint32_t value);
esp_err_t keemash_keelink_put_u64(keemash_keelink_writer_t *writer,
				  uint16_t field_id, uint64_t value);
esp_err_t keemash_keelink_put_bool(keemash_keelink_writer_t *writer,
				   uint16_t field_id, bool value);
esp_err_t keemash_keelink_put_utf8(keemash_keelink_writer_t *writer,
				   uint16_t field_id, const char *value);
void keemash_keelink_reader_init(keemash_keelink_reader_t *reader,
				  const void *payload, size_t payload_len);
esp_err_t keemash_keelink_reader_next(keemash_keelink_reader_t *reader,
				      keemash_keelink_tlv_t *tlv);
bool keemash_keelink_tlv_u32(const keemash_keelink_tlv_t *tlv, uint32_t *value);
bool keemash_keelink_tlv_u64(const keemash_keelink_tlv_t *tlv, uint64_t *value);
bool keemash_keelink_tlv_bool(const keemash_keelink_tlv_t *tlv, bool *value);
size_t keemash_keelink_tlv_copy_text(const keemash_keelink_tlv_t *tlv,
				     char *out, size_t out_size);
bool keemash_keelink_selftest(void);

#ifdef __cplusplus
}
#endif
