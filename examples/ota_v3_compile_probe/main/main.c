// SPDX-License-Identifier: GPL-2.0-only

#include "keemash_ota_v3.h"

void app_main(void)
{
	(void)keemash_ota_v3_verify_signed_fields;
	(void)keemash_ota_v3_verify_package(NULL, NULL, 0U, NULL);
}
