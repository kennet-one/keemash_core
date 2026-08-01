// SPDX-License-Identifier: Apache-2.0

#include "keemash_mesh_network.h"

#include "esp_mesh.h"

esp_err_t keemash_mesh_apply_single_root_policy(
	keemash_mesh_network_role_t role)
{
	mesh_type_t mesh_type;
	switch (role) {
	case KEEMASH_MESH_ROLE_ROOT:
		mesh_type = MESH_ROOT;
		break;
	case KEEMASH_MESH_ROLE_NODE:
		mesh_type = MESH_NODE;
		break;
	case KEEMASH_MESH_ROLE_LEAF:
		mesh_type = MESH_LEAF;
		break;
	default:
		return ESP_ERR_INVALID_ARG;
	}

	esp_err_t err = esp_mesh_fix_root(true);
	if (err != ESP_OK) return err;
	err = esp_mesh_allow_root_conflicts(false);
	if (err != ESP_OK) return err;
	return esp_mesh_set_type(mesh_type);
}
