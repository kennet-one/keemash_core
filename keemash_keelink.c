// SPDX-License-Identifier: Apache-2.0
#include "keemash_keelink.h"

#include <string.h>

static const uint8_t s_magic[4] = {'K', 'L', 'N', 'K'};

static void put_u16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
}

static void put_u32(uint8_t *p, uint32_t v)
{
	for (unsigned i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (i * 8));
}

static void put_u64(uint8_t *p, uint64_t v)
{
	for (unsigned i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (i * 8));
}

static uint16_t get_u16(const uint8_t *p)
{
	return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t get_u32(const uint8_t *p)
{
	uint32_t v = 0;
	for (unsigned i = 0; i < 4; i++) v |= (uint32_t)p[i] << (i * 8);
	return v;
}

static uint64_t get_u64(const uint8_t *p)
{
	uint64_t v = 0;
	for (unsigned i = 0; i < 8; i++) v |= (uint64_t)p[i] << (i * 8);
	return v;
}

esp_err_t keemash_keelink_encode_header(uint8_t out[KEEMASH_KEELINK_HEADER_SIZE],
					const keemash_keelink_header_t *header)
{
	if (!out || !header || header->kind < KEEMASH_KEELINK_HELLO ||
	    header->kind > KEEMASH_KEELINK_ERROR ||
	    header->payload_len > KEEMASH_KEELINK_MAX_PAYLOAD) {
		return ESP_ERR_INVALID_ARG;
	}
	memset(out, 0, KEEMASH_KEELINK_HEADER_SIZE);
	memcpy(out, s_magic, sizeof(s_magic));
	out[4] = KEEMASH_KEELINK_VERSION;
	out[5] = header->kind;
	put_u16(out + 6, header->flags);
	put_u16(out + 8, header->channel);
	put_u16(out + 10, KEEMASH_KEELINK_HEADER_SIZE);
	put_u32(out + 12, header->payload_len);
	put_u64(out + 16, header->session_id);
	put_u32(out + 24, header->message_id);
	put_u32(out + 28, header->correlation_id);
	return ESP_OK;
}

esp_err_t keemash_keelink_decode_header(const void *frame, size_t frame_len,
					keemash_keelink_header_t *header)
{
	if (!frame || !header || frame_len < KEEMASH_KEELINK_HEADER_SIZE) {
		return ESP_ERR_INVALID_SIZE;
	}
	const uint8_t *p = frame;
	if (memcmp(p, s_magic, sizeof(s_magic)) != 0 ||
	    p[4] != KEEMASH_KEELINK_VERSION ||
	    get_u16(p + 10) != KEEMASH_KEELINK_HEADER_SIZE) {
		return ESP_ERR_INVALID_VERSION;
	}
	uint32_t payload_len = get_u32(p + 12);
	if (payload_len > KEEMASH_KEELINK_MAX_PAYLOAD ||
	    frame_len != KEEMASH_KEELINK_HEADER_SIZE + payload_len) {
		return ESP_ERR_INVALID_SIZE;
	}
	header->kind = p[5];
	header->flags = get_u16(p + 6);
	header->channel = get_u16(p + 8);
	header->payload_len = payload_len;
	header->session_id = get_u64(p + 16);
	header->message_id = get_u32(p + 24);
	header->correlation_id = get_u32(p + 28);
	if (header->kind < KEEMASH_KEELINK_HELLO ||
	    header->kind > KEEMASH_KEELINK_ERROR) return ESP_ERR_NOT_SUPPORTED;
	return ESP_OK;
}

size_t keemash_keelink_frame_size(const keemash_keelink_header_t *header)
{
	return header && header->payload_len <= KEEMASH_KEELINK_MAX_PAYLOAD
		? KEEMASH_KEELINK_HEADER_SIZE + header->payload_len : 0;
}

void keemash_keelink_writer_init(keemash_keelink_writer_t *writer,
				  void *buffer, size_t capacity)
{
	if (!writer) return;
	writer->buffer = buffer;
	writer->capacity = buffer ? capacity : 0;
	writer->length = 0;
}

esp_err_t keemash_keelink_put(keemash_keelink_writer_t *writer,
			      uint16_t field_id, uint8_t type, uint8_t flags,
			      const void *data, size_t length)
{
	if (!writer || !writer->buffer || field_id == 0 ||
	    type < KEEMASH_KEELINK_TLV_U32 || type > KEEMASH_KEELINK_TLV_UTF8 ||
	    length > UINT16_MAX || (length && !data)) return ESP_ERR_INVALID_ARG;
	if (writer->length + KEEMASH_KEELINK_TLV_HEADER_SIZE + length >
	    writer->capacity) return ESP_ERR_NO_MEM;
	uint8_t *p = writer->buffer + writer->length;
	put_u16(p, field_id);
	p[2] = type;
	p[3] = flags;
	put_u16(p + 4, (uint16_t)length);
	if (length) memcpy(p + KEEMASH_KEELINK_TLV_HEADER_SIZE, data, length);
	writer->length += KEEMASH_KEELINK_TLV_HEADER_SIZE + length;
	return ESP_OK;
}

esp_err_t keemash_keelink_put_u32(keemash_keelink_writer_t *writer,
				  uint16_t field_id, uint32_t value)
{
	uint8_t data[4];
	put_u32(data, value);
	return keemash_keelink_put(writer, field_id, KEEMASH_KEELINK_TLV_U32,
				    0, data, sizeof(data));
}

esp_err_t keemash_keelink_put_u64(keemash_keelink_writer_t *writer,
				  uint16_t field_id, uint64_t value)
{
	uint8_t data[8];
	put_u64(data, value);
	return keemash_keelink_put(writer, field_id, KEEMASH_KEELINK_TLV_U64,
				    0, data, sizeof(data));
}

esp_err_t keemash_keelink_put_bool(keemash_keelink_writer_t *writer,
				   uint16_t field_id, bool value)
{
	uint8_t data = value ? 1 : 0;
	return keemash_keelink_put(writer, field_id, KEEMASH_KEELINK_TLV_BOOL,
				    0, &data, sizeof(data));
}

esp_err_t keemash_keelink_put_utf8(keemash_keelink_writer_t *writer,
				   uint16_t field_id, const char *value)
{
	if (!value) return ESP_ERR_INVALID_ARG;
	return keemash_keelink_put(writer, field_id, KEEMASH_KEELINK_TLV_UTF8,
				    0, value, strlen(value));
}

void keemash_keelink_reader_init(keemash_keelink_reader_t *reader,
				  const void *payload, size_t payload_len)
{
	if (!reader) return;
	reader->buffer = payload;
	reader->length = payload ? payload_len : 0;
	reader->offset = 0;
}

esp_err_t keemash_keelink_reader_next(keemash_keelink_reader_t *reader,
				      keemash_keelink_tlv_t *tlv)
{
	if (!reader || !tlv) return ESP_ERR_INVALID_ARG;
	if (reader->offset == reader->length) return ESP_ERR_NOT_FOUND;
	if (reader->offset + KEEMASH_KEELINK_TLV_HEADER_SIZE > reader->length)
		return ESP_ERR_INVALID_SIZE;
	const uint8_t *p = reader->buffer + reader->offset;
	uint16_t length = get_u16(p + 4);
	if (reader->offset + KEEMASH_KEELINK_TLV_HEADER_SIZE + length >
	    reader->length) return ESP_ERR_INVALID_SIZE;
	tlv->field_id = get_u16(p);
	tlv->type = p[2];
	tlv->flags = p[3];
	tlv->length = length;
	tlv->data = p + KEEMASH_KEELINK_TLV_HEADER_SIZE;
	reader->offset += KEEMASH_KEELINK_TLV_HEADER_SIZE + length;
	return ESP_OK;
}

bool keemash_keelink_tlv_u32(const keemash_keelink_tlv_t *tlv, uint32_t *value)
{
	if (!tlv || !value || tlv->type != KEEMASH_KEELINK_TLV_U32 ||
	    tlv->length != 4) return false;
	*value = get_u32(tlv->data);
	return true;
}

bool keemash_keelink_tlv_u64(const keemash_keelink_tlv_t *tlv, uint64_t *value)
{
	if (!tlv || !value || tlv->type != KEEMASH_KEELINK_TLV_U64 ||
	    tlv->length != 8) return false;
	*value = get_u64(tlv->data);
	return true;
}

bool keemash_keelink_tlv_bool(const keemash_keelink_tlv_t *tlv, bool *value)
{
	if (!tlv || !value || tlv->type != KEEMASH_KEELINK_TLV_BOOL ||
	    tlv->length != 1 || tlv->data[0] > 1) return false;
	*value = tlv->data[0] != 0;
	return true;
}

size_t keemash_keelink_tlv_copy_text(const keemash_keelink_tlv_t *tlv,
				     char *out, size_t out_size)
{
	if (!tlv || !out || out_size == 0 ||
	    tlv->type != KEEMASH_KEELINK_TLV_UTF8) return 0;
	size_t length = tlv->length < out_size - 1 ? tlv->length : out_size - 1;
	memcpy(out, tlv->data, length);
	out[length] = '\0';
	return length;
}

bool keemash_keelink_selftest(void)
{
	static const uint8_t golden[] = {
		0x4b,0x4c,0x4e,0x4b,0x01,0x01,0x00,0x00,0x01,0x00,0x20,0x00,
		0x15,0x00,0x00,0x00,0x08,0x07,0x06,0x05,0x04,0x03,0x02,0x01,
		0x09,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x06,0x00,
		0x05,0x00,0x6e,0x6f,0x64,0x65,0x30,0x02,0x00,0x01,0x00,0x04,
		0x00,0x78,0x56,0x34,0x12,
	};
	uint8_t frame[128] = {0};
	keemash_keelink_writer_t writer;
	keemash_keelink_writer_init(&writer, frame + KEEMASH_KEELINK_HEADER_SIZE,
				     sizeof(frame) - KEEMASH_KEELINK_HEADER_SIZE);
	if (keemash_keelink_put_utf8(&writer, 1, "node0") != ESP_OK ||
	    keemash_keelink_put_u32(&writer, 2, 0x12345678) != ESP_OK) return false;
	keemash_keelink_header_t header = {
		.kind = KEEMASH_KEELINK_HELLO,
		.channel = KEEMASH_KEELINK_CH_SYSTEM,
		.payload_len = writer.length,
		.session_id = 0x0102030405060708ULL,
		.message_id = 9,
	};
	if (keemash_keelink_encode_header(frame, &header) != ESP_OK) return false;
	if (KEEMASH_KEELINK_HEADER_SIZE + writer.length != sizeof(golden) ||
	    memcmp(frame, golden, sizeof(golden)) != 0) return false;
	keemash_keelink_header_t decoded = {0};
	if (keemash_keelink_decode_header(frame,
		KEEMASH_KEELINK_HEADER_SIZE + writer.length, &decoded) != ESP_OK ||
	    decoded.session_id != header.session_id || decoded.message_id != 9) return false;
	keemash_keelink_reader_t reader;
	keemash_keelink_reader_init(&reader, frame + KEEMASH_KEELINK_HEADER_SIZE,
				     decoded.payload_len);
	keemash_keelink_tlv_t tlv;
	char text[8];
	return keemash_keelink_reader_next(&reader, &tlv) == ESP_OK &&
	       keemash_keelink_tlv_copy_text(&tlv, text, sizeof(text)) == 5 &&
	       strcmp(text, "node0") == 0;
}
