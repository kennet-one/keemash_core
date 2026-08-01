// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	KEEMASH_MESH_ROLE_ROOT = 0,
	KEEMASH_MESH_ROLE_NODE,
	KEEMASH_MESH_ROLE_LEAF,
} keemash_mesh_network_role_t;

/**
 * Apply the KeeMASH single-root contract before esp_mesh_start().
 *
 * Wi-Fi must already be started and ESP-MESH must already be initialized.
 * The helper enables fixed-root mode on every participant, disables split
 * roots and assigns the requested ESP-MESH role. Credentials, topology and
 * recovery policy remain owned by the firmware transport adapter.
 */
esp_err_t keemash_mesh_apply_single_root_policy(
	keemash_mesh_network_role_t role);

#ifdef __cplusplus
}
#endif
