// SPDX-License-Identifier: Apache-2.0
#include "keemash_log_time_vprintf.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "esp_log.h"

static bool s_started;
static bool s_enabled = true;

static bool local_time_string(char *out, size_t out_size)
{
	if (!out || out_size < 20) return false;
	time_t now = 0;
	struct tm local = {0};
	time(&now);
	if (!localtime_r(&now, &local) || local.tm_year < (2020 - 1900)) return false;
	return strftime(out, out_size, "%Y-%m-%d %H:%M:%S", &local) > 0;
}

static bool is_idf_log_line(const char *line)
{
	if (!line || line[1] != ' ') return false;
	return line[0] == 'E' || line[0] == 'W' || line[0] == 'I' ||
	       line[0] == 'D' || line[0] == 'V';
}

static int timestamp_vprintf(const char *format, va_list args)
{
	char original[256];
	char output[320];
	char timestamp[32];
	va_list copy;
	va_copy(copy, args);
	(void)vsnprintf(original, sizeof(original), format, copy);
	va_end(copy);
	original[sizeof(original) - 1] = '\0';

	bool have_time = s_enabled && local_time_string(timestamp, sizeof(timestamp));
	if (have_time && is_idf_log_line(original)) {
		char *closing = strchr(original, ')');
		if (closing && closing[1] == ' ') {
			int prefix_len = (int)((closing - original) + 2);
			(void)snprintf(output, sizeof(output), "%.*s[%s] %s",
			               prefix_len, original, timestamp, original + prefix_len);
		} else {
			(void)snprintf(output, sizeof(output), "%s [%s]", original, timestamp);
		}
	} else if (have_time) {
		(void)snprintf(output, sizeof(output), "[%s] %s", timestamp, original);
	} else {
		(void)snprintf(output, sizeof(output), "%s", original);
	}
	fputs(output, stdout);
	return (int)strlen(output);
}

esp_err_t keemash_log_time_vprintf_start(void)
{
	if (s_started) return ESP_OK;
	(void)esp_log_set_vprintf(timestamp_vprintf);
	s_started = true;
	return ESP_OK;
}

void keemash_log_time_vprintf_enable(bool enabled)
{
	s_enabled = enabled;
}
