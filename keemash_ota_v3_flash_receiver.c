// SPDX-License-Identifier: GPL-2.0-only

#include "keemash_ota_v3_flash_receiver.h"

#include <stdlib.h>
#include <string.h>

#include "esp_ota_ops.h"
#include "keemash_ota_v3_checkpoint.h"

#ifdef CONFIG_KEEMASH_OTA_V3_CHECKPOINT_BYTES
#define CHECKPOINT_INTERVAL CONFIG_KEEMASH_OTA_V3_CHECKPOINT_BYTES
#else
#define CHECKPOINT_INTERVAL 65536U
#endif

struct keemash_ota_v3_flash_receiver {
	keemash_ota_v3_stream_t *stream;
	const esp_partition_t *partition;
	esp_ota_handle_t handle;
	keemash_ota_v3_signed_fields_t fields;
	uint8_t operation_id[16];
	uint8_t artifact_id[KEEMASH_OTA_V3_SHA256_LEN];
	uint8_t signature[KEEMASH_OTA_V3_SIGNATURE_LEN];
	uint8_t signed_fields[KEEMASH_OTA_V3_SIGNED_FIELDS_MAX];
	size_t signed_fields_len;
	uint32_t checkpoint_raw_offset;
	bool active;
	bool verified;
	bool resumed;
};

static esp_err_t flash_output(const uint8_t *bytes, size_t length, void *context)
{
	keemash_ota_v3_flash_receiver_t *receiver = context;
	return esp_ota_write(receiver->handle, bytes, length);
}

static esp_err_t flash_read(uint32_t offset, uint8_t *bytes,
			    size_t length, void *context)
{
	const esp_partition_t *partition = context;
	return esp_partition_read(partition, offset, bytes, length);
}

static void close_active_handle(keemash_ota_v3_flash_receiver_t *receiver)
{
	if (receiver->active) (void)esp_ota_abort(receiver->handle);
	receiver->active = false;
}

static void reset_receiver(keemash_ota_v3_flash_receiver_t *receiver)
{
	close_active_handle(receiver);
	if (receiver->stream) {
		keemash_ota_v3_stream_end(receiver->stream);
		free(receiver->stream);
	}
	memset(receiver, 0, sizeof(*receiver));
}

static esp_err_t fail_receiver(keemash_ota_v3_flash_receiver_t *receiver,
			       esp_err_t error)
{
	(void)keemash_ota_v3_checkpoint_clear();
	reset_receiver(receiver);
	return error;
}

esp_err_t keemash_ota_v3_flash_receiver_create(
	keemash_ota_v3_flash_receiver_t **out)
{
	if (!out) return ESP_ERR_INVALID_ARG;
	*out = calloc(1U, sizeof(**out));
	return *out ? ESP_OK : ESP_ERR_NO_MEM;
}

static bool same_operation(const keemash_ota_v3_flash_receiver_t *receiver,
			   const uint8_t operation_id[16],
			   const uint8_t artifact_id[KEEMASH_OTA_V3_SHA256_LEN])
{
	return memcmp(receiver->operation_id, operation_id, 16U) == 0 &&
		memcmp(receiver->artifact_id, artifact_id,
		       KEEMASH_OTA_V3_SHA256_LEN) == 0;
}

esp_err_t keemash_ota_v3_flash_receiver_prepare(
	keemash_ota_v3_flash_receiver_t *receiver,
	const uint8_t operation_id[16],
	const uint8_t artifact_id[KEEMASH_OTA_V3_SHA256_LEN],
	const uint8_t *signed_fields, size_t signed_fields_len,
	const uint8_t signature[KEEMASH_OTA_V3_SIGNATURE_LEN],
	const char *project_name, const char *chip_target,
	uint32_t core_version, uint32_t fabric_schema,
	keemash_ota_v3_preflight_fn preflight, void *preflight_context)
{
	if (!receiver || !operation_id || !artifact_id || !signed_fields ||
	    signed_fields_len == 0U ||
	    signed_fields_len > KEEMASH_OTA_V3_SIGNED_FIELDS_MAX ||
	    !signature || !project_name || !chip_target || !preflight) {
		return ESP_ERR_INVALID_ARG;
	}
	if (receiver->active || receiver->verified) {
		return same_operation(receiver, operation_id, artifact_id) &&
		       receiver->signed_fields_len == signed_fields_len &&
		       memcmp(receiver->signed_fields, signed_fields,
			      signed_fields_len) == 0 &&
		       memcmp(receiver->signature, signature,
			      KEEMASH_OTA_V3_SIGNATURE_LEN) == 0
			? ESP_OK : ESP_ERR_INVALID_STATE;
	}
	keemash_ota_v3_signed_fields_t fields;
	esp_err_t err = keemash_ota_v3_verify_signed_fields(
		signed_fields, signed_fields_len, signature,
		KEEMASH_OTA_V3_SIGNATURE_LEN, &fields);
	if (err != ESP_OK) return err;
	err = preflight(preflight_context);
	if (err != ESP_OK) return err;
	const esp_partition_t *partition = esp_ota_get_next_update_partition(NULL);
	if (!partition) return ESP_ERR_NOT_FOUND;
	err = keemash_ota_v3_check_target(&fields, project_name, chip_target,
		partition->size, core_version, fabric_schema);
	if (err != ESP_OK) return err;

	keemash_ota_v3_checkpoint_t *checkpoint = malloc(sizeof(*checkpoint));
	if (!checkpoint) return ESP_ERR_NO_MEM;
	esp_err_t checkpoint_err = keemash_ota_v3_checkpoint_load(checkpoint);
	if (checkpoint_err != ESP_OK && checkpoint_err != ESP_ERR_NOT_FOUND) {
		free(checkpoint);
		return checkpoint_err;
	}
	bool resume = checkpoint_err == ESP_OK;
	if (resume &&
	    (memcmp(checkpoint->operation_id, operation_id, 16U) != 0 ||
	     memcmp(checkpoint->artifact_id, artifact_id,
		    KEEMASH_OTA_V3_SHA256_LEN) != 0 ||
	     checkpoint->signed_fields_len != signed_fields_len ||
	     memcmp(checkpoint->signed_fields, signed_fields,
		    signed_fields_len) != 0 ||
	     memcmp(checkpoint->signature, signature,
		    KEEMASH_OTA_V3_SIGNATURE_LEN) != 0 ||
	     strcmp(checkpoint->partition_label, partition->label) != 0)) {
		free(checkpoint);
		return ESP_ERR_INVALID_STATE;
	}
	receiver->stream = calloc(1U, sizeof(*receiver->stream));
	if (!receiver->stream) {
		free(checkpoint);
		return ESP_ERR_NO_MEM;
	}
	receiver->partition = partition;
	receiver->fields = fields;
	if (resume) {
		err = keemash_ota_v3_stream_resume(
			receiver->stream, &fields, &checkpoint->resume,
			flash_read, (void *)partition, flash_output, receiver);
		if (err == ESP_OK) {
			err = esp_ota_resume(partition, OTA_WITH_SEQUENTIAL_WRITES,
				checkpoint->resume.raw_offset, &receiver->handle);
		}
		if (err == ESP_OK) {
			receiver->checkpoint_raw_offset = checkpoint->resume.raw_offset;
			receiver->resumed = true;
		}
	} else {
		err = keemash_ota_v3_stream_begin(
			receiver->stream, &fields, flash_output, receiver);
		if (err == ESP_OK) {
			err = esp_ota_begin(partition, OTA_WITH_SEQUENTIAL_WRITES,
					    &receiver->handle);
		}
	}
	free(checkpoint);
	if (err != ESP_OK) {
		reset_receiver(receiver);
		return err;
	}
	memcpy(receiver->operation_id, operation_id, 16U);
	memcpy(receiver->artifact_id, artifact_id, KEEMASH_OTA_V3_SHA256_LEN);
	memcpy(receiver->signature, signature, KEEMASH_OTA_V3_SIGNATURE_LEN);
	memcpy(receiver->signed_fields, signed_fields, signed_fields_len);
	receiver->signed_fields_len = signed_fields_len;
	receiver->active = true;
	return ESP_OK;
}

esp_err_t keemash_ota_v3_flash_receiver_write(
	keemash_ota_v3_flash_receiver_t *receiver,
	const keemash_fabric_v2_FirmwareBlockDescriptor *descriptor,
	uint32_t block_encoded_offset, const uint8_t *chunk,
	size_t chunk_size, bool final_chunk)
{
	if (!receiver || !receiver->active) return ESP_ERR_INVALID_STATE;
	esp_err_t err = keemash_ota_v3_stream_feed(receiver->stream,
		descriptor, block_encoded_offset, chunk, chunk_size, final_chunk);
	if (err != ESP_OK) return fail_receiver(receiver, err);
	const keemash_ota_v3_stream_t *stream = receiver->stream;
	if (stream->raw_offset == receiver->checkpoint_raw_offset ||
	    stream->raw_offset == 0U ||
	    stream->raw_offset >= receiver->fields.raw_size ||
	    stream->raw_offset % CHECKPOINT_INTERVAL != 0U) {
		return ESP_OK;
	}
	keemash_ota_v3_checkpoint_t *checkpoint = calloc(1U, sizeof(*checkpoint));
	if (!checkpoint) return fail_receiver(receiver, ESP_ERR_NO_MEM);
	memcpy(checkpoint->operation_id, receiver->operation_id, 16U);
	memcpy(checkpoint->artifact_id, receiver->artifact_id,
	       KEEMASH_OTA_V3_SHA256_LEN);
	memcpy(checkpoint->signature, receiver->signature,
	       KEEMASH_OTA_V3_SIGNATURE_LEN);
	checkpoint->signed_fields_len = (uint16_t)receiver->signed_fields_len;
	memcpy(checkpoint->signed_fields, receiver->signed_fields,
	       receiver->signed_fields_len);
	strncpy(checkpoint->partition_label, receiver->partition->label,
		sizeof(checkpoint->partition_label) - 1U);
	err = keemash_ota_v3_stream_checkpoint(receiver->stream,
		&checkpoint->resume);
	if (err == ESP_OK) err = keemash_ota_v3_checkpoint_save(checkpoint);
	free(checkpoint);
	if (err != ESP_OK) return fail_receiver(receiver, err);
	receiver->checkpoint_raw_offset = stream->raw_offset;
	return ESP_OK;
}

esp_err_t keemash_ota_v3_flash_receiver_verify(
	keemash_ota_v3_flash_receiver_t *receiver,
	const esp_partition_t **verified_partition)
{
	if (!receiver || !receiver->active || !verified_partition) {
		return ESP_ERR_INVALID_STATE;
	}
	esp_err_t err = keemash_ota_v3_stream_finish(receiver->stream);
	if (err != ESP_OK) return fail_receiver(receiver, err);
	err = esp_ota_end(receiver->handle);
	receiver->active = false;
	if (err != ESP_OK) return fail_receiver(receiver, err);
	receiver->verified = true;
	*verified_partition = receiver->partition;
	return ESP_OK;
}

esp_err_t keemash_ota_v3_flash_receiver_abort(
	keemash_ota_v3_flash_receiver_t *receiver,
	const uint8_t operation_id[16],
	const uint8_t artifact_id[KEEMASH_OTA_V3_SHA256_LEN])
{
	if (!receiver || !operation_id || !artifact_id) return ESP_ERR_INVALID_ARG;
	if ((receiver->active || receiver->verified) &&
	    !same_operation(receiver, operation_id, artifact_id)) {
		return ESP_ERR_INVALID_STATE;
	}
	if (!receiver->active && !receiver->verified) {
		keemash_ota_v3_checkpoint_t *checkpoint = malloc(sizeof(*checkpoint));
		if (!checkpoint) return ESP_ERR_NO_MEM;
		esp_err_t load_err = keemash_ota_v3_checkpoint_load(checkpoint);
		if (load_err == ESP_OK &&
		    (memcmp(checkpoint->operation_id, operation_id, 16U) != 0 ||
		     memcmp(checkpoint->artifact_id, artifact_id,
			    KEEMASH_OTA_V3_SHA256_LEN) != 0)) {
			load_err = ESP_ERR_INVALID_STATE;
		}
		free(checkpoint);
		if (load_err != ESP_OK) return load_err;
	}
	esp_err_t err = keemash_ota_v3_checkpoint_clear();
	if (err != ESP_OK) return err;
	reset_receiver(receiver);
	return ESP_OK;
}

static void operation_bytes(const keemash_fabric_v2_Id128 *id,
	uint8_t bytes[16])
{
	for (size_t i = 0; i < 8U; ++i) {
		bytes[i] = (uint8_t)(id->high >> (56U - 8U * i));
		bytes[8U + i] = (uint8_t)(id->low >> (56U - 8U * i));
	}
}

static bool matching_transfer(const keemash_ota_v3_flash_receiver_t *receiver,
	const keemash_fabric_v2_Id128 *id, const uint8_t *artifact_id,
	size_t artifact_id_len)
{
	if (artifact_id_len != KEEMASH_OTA_V3_SHA256_LEN ||
	    (!receiver->active && !receiver->verified)) return false;
	uint8_t operation_id[16];
	operation_bytes(id, operation_id);
	return same_operation(receiver, operation_id, artifact_id);
}

static esp_err_t match_persisted_transfer(
	const keemash_fabric_v2_Id128 *id, const uint8_t *artifact_id,
	size_t artifact_id_len)
{
	if (artifact_id_len != KEEMASH_OTA_V3_SHA256_LEN)
		return ESP_ERR_INVALID_ARG;
	keemash_ota_v3_checkpoint_t *checkpoint = malloc(sizeof(*checkpoint));
	if (!checkpoint) return ESP_ERR_NO_MEM;
	esp_err_t err = keemash_ota_v3_checkpoint_load(checkpoint);
	if (err == ESP_OK) {
		uint8_t operation_id[16];
		operation_bytes(id, operation_id);
		if (memcmp(checkpoint->operation_id, operation_id,
			   sizeof(operation_id)) != 0 ||
		    memcmp(checkpoint->artifact_id, artifact_id,
			   KEEMASH_OTA_V3_SHA256_LEN) != 0) {
			err = ESP_ERR_NOT_FOUND;
		}
	}
	free(checkpoint);
	return err;
}

esp_err_t keemash_ota_v3_flash_receiver_handle_transfer(
	keemash_ota_v3_flash_receiver_t *receiver,
	const keemash_fabric_v2_OtaTransfer *transfer,
	const char *project_name, const char *chip_target,
	uint32_t core_version, uint32_t fabric_schema,
	keemash_ota_v3_preflight_fn preflight, void *preflight_context,
	const esp_partition_t **verified_partition)
{
	if (!receiver || !transfer || !verified_partition)
		return ESP_ERR_INVALID_ARG;
	*verified_partition = NULL;
	switch (transfer->which_body) {
	case keemash_fabric_v2_OtaTransfer_prepare_tag: {
		const keemash_fabric_v2_OtaPrepare *prepare =
			&transfer->body.prepare;
		if (!prepare->has_operation_id ||
		    prepare->artifact_id.size != KEEMASH_OTA_V3_SHA256_LEN ||
		    prepare->signature.size != KEEMASH_OTA_V3_SIGNATURE_LEN ||
		    prepare->signed_fields.size == 0U ||
		    (prepare->requested_chunk_size != 0U &&
		     prepare->requested_chunk_size != 1024U &&
		     prepare->requested_chunk_size != 2048U) ||
		    prepare->requested_window > 4U)
			return ESP_ERR_INVALID_ARG;
		uint8_t operation_id[16];
		operation_bytes(&prepare->operation_id, operation_id);
		return keemash_ota_v3_flash_receiver_prepare(receiver,
			operation_id, prepare->artifact_id.bytes,
			prepare->signed_fields.bytes,
			prepare->signed_fields.size, prepare->signature.bytes,
			project_name, chip_target, core_version, fabric_schema,
			preflight, preflight_context);
	}
	case keemash_fabric_v2_OtaTransfer_data_tag: {
		const keemash_fabric_v2_OtaBlockChunk *data =
			&transfer->body.data;
		if (!data->has_operation_id || !data->has_block ||
		    data->data.size == 0U ||
		    !matching_transfer(receiver, &data->operation_id,
			data->artifact_id.bytes, data->artifact_id.size))
			return ESP_ERR_INVALID_ARG;
		return keemash_ota_v3_flash_receiver_write(receiver,
			&data->block, data->block_encoded_offset,
			data->data.bytes, data->data.size, data->final_chunk);
	}
	case keemash_fabric_v2_OtaTransfer_commit_tag: {
		const keemash_fabric_v2_OtaCommit *commit =
			&transfer->body.commit;
		if (!commit->has_operation_id ||
		    !matching_transfer(receiver, &commit->operation_id,
			commit->artifact_id.bytes, commit->artifact_id.size) ||
		    commit->block_table_sha256.size != KEEMASH_OTA_V3_SHA256_LEN ||
		    commit->image_sha256.size != KEEMASH_OTA_V3_SHA256_LEN ||
		    memcmp(commit->block_table_sha256.bytes,
			receiver->fields.block_table_sha256,
			KEEMASH_OTA_V3_SHA256_LEN) != 0 ||
		    memcmp(commit->image_sha256.bytes,
			receiver->fields.image_sha256,
			KEEMASH_OTA_V3_SHA256_LEN) != 0)
			return ESP_ERR_INVALID_ARG;
		if (receiver->verified) {
			*verified_partition = receiver->partition;
			return ESP_OK;
		}
		return keemash_ota_v3_flash_receiver_verify(receiver,
			verified_partition);
	}
	case keemash_fabric_v2_OtaTransfer_abort_tag: {
		const keemash_fabric_v2_OtaAbort *abort =
			&transfer->body.abort;
		if (!abort->has_operation_id ||
		    abort->artifact_id.size != KEEMASH_OTA_V3_SHA256_LEN)
			return ESP_ERR_INVALID_ARG;
		uint8_t operation_id[16];
		operation_bytes(&abort->operation_id, operation_id);
		return keemash_ota_v3_flash_receiver_abort(receiver,
			operation_id, abort->artifact_id.bytes);
	}
	case keemash_fabric_v2_OtaTransfer_query_tag: {
		const keemash_fabric_v2_OtaQuery *query =
			&transfer->body.query;
		if (!query->has_operation_id) return ESP_ERR_INVALID_ARG;
		if (matching_transfer(receiver, &query->operation_id,
			query->artifact_id.bytes, query->artifact_id.size))
			return ESP_OK;
		return match_persisted_transfer(&query->operation_id,
			query->artifact_id.bytes, query->artifact_id.size);
	}
	default:
		return ESP_ERR_NOT_SUPPORTED;
	}
}

void keemash_ota_v3_flash_receiver_status(
	const keemash_ota_v3_flash_receiver_t *receiver,
	keemash_ota_v3_flash_status_t *status)
{
	if (!status) return;
	memset(status, 0, sizeof(*status));
	if (!receiver) return;
	status->active = receiver->active;
	status->verified = receiver->verified;
	status->resumed = receiver->resumed;
	if (!receiver->stream) return;
	status->raw_offset = receiver->stream->raw_offset;
	status->encoded_offset = receiver->stream->encoded_offset;
	status->next_block_index = receiver->stream->next_block_index;
}

void keemash_ota_v3_flash_receiver_destroy(
	keemash_ota_v3_flash_receiver_t *receiver)
{
	if (!receiver) return;
	reset_receiver(receiver);
	free(receiver);
}
