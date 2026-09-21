// SPDX-License-Identifier: GPL-2.0-only

#include "keemash_ota_v3.h"

#include <limits.h>
#include <string.h>

esp_err_t keemash_ota_v3_inflater_begin(
	keemash_ota_v3_inflater_t *inflater, uint32_t expected_raw_size,
	keemash_ota_v3_output_fn output_fn, void *output_context)
{
	if (!inflater || !output_fn || expected_raw_size == 0U ||
	    expected_raw_size > KEEMASH_OTA_V3_FULL_BLOCK_SIZE) {
		return ESP_ERR_INVALID_ARG;
	}
	memset(inflater, 0, sizeof(*inflater));
	inflater->expected_raw_size = expected_raw_size;
	inflater->output_fn = output_fn;
	inflater->output_context = output_context;
	if (inflateInit2(&inflater->stream, -(int)KEEMASH_OTA_V3_DEFLATE_WINDOW_BITS) != Z_OK) {
		return ESP_ERR_NO_MEM;
	}
	inflater->active = true;
	return ESP_OK;
}

esp_err_t keemash_ota_v3_inflater_feed(
	keemash_ota_v3_inflater_t *inflater, const uint8_t *encoded,
	size_t encoded_size, bool final_chunk)
{
	if (!inflater || !inflater->active ||
	    (encoded_size != 0U && !encoded) || encoded_size > UINT_MAX) {
		return ESP_ERR_INVALID_ARG;
	}
	inflater->stream.next_in = (Bytef *)encoded;
	inflater->stream.avail_in = (uInt)encoded_size;
	for (;;) {
		inflater->stream.next_out = inflater->output;
		inflater->stream.avail_out = sizeof(inflater->output);
		uInt before_in = inflater->stream.avail_in;
		int result = inflate(&inflater->stream,
			final_chunk ? Z_FINISH : Z_NO_FLUSH);
		size_t produced = sizeof(inflater->output) - inflater->stream.avail_out;
		if (produced != 0U) {
			if (produced > inflater->expected_raw_size - inflater->produced_raw_size) {
				return ESP_ERR_INVALID_SIZE;
			}
			esp_err_t err = inflater->output_fn(
				inflater->output, produced, inflater->output_context);
			if (err != ESP_OK) return err;
			inflater->produced_raw_size += (uint32_t)produced;
		}
		if (result == Z_STREAM_END) {
			if (!final_chunk || inflater->stream.avail_in != 0U ||
			    inflater->produced_raw_size != inflater->expected_raw_size) {
				return ESP_ERR_INVALID_RESPONSE;
			}
			return ESP_OK;
		}
		if (result != Z_OK && result != Z_BUF_ERROR) {
			return ESP_ERR_INVALID_RESPONSE;
		}
		if (before_in == inflater->stream.avail_in && produced == 0U) {
			return final_chunk ? ESP_ERR_INVALID_RESPONSE : ESP_OK;
		}
		if (!final_chunk && inflater->stream.avail_in == 0U && produced == 0U) {
			return ESP_OK;
		}
		if (!final_chunk && inflater->stream.avail_in == 0U &&
		    inflater->stream.avail_out != 0U) {
			return ESP_OK;
		}
	}
}

void keemash_ota_v3_inflater_end(keemash_ota_v3_inflater_t *inflater)
{
	if (!inflater || !inflater->active) return;
	(void)inflateEnd(&inflater->stream);
	inflater->active = false;
}
