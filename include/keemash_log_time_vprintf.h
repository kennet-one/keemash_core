// SPDX-License-Identifier: GPL-2.0-only
#pragma once

#include <stdbool.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

esp_err_t keemash_log_time_vprintf_start(void);
void keemash_log_time_vprintf_enable(bool enabled);

#ifdef __cplusplus
}
#endif
