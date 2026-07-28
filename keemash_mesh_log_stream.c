// SPDX-License-Identifier: Apache-2.0
#include "keemash_mesh_log_stream.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "esp_log.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#include "sdkconfig.h"

#include "keemash_mesh_node.h"
#include "keemash_mesh_proto.h"
#include "keemash_mesh_hooks.h"

static const char *TAG = "mesh_log";

typedef int (*vprintf_like_t)(const char *fmt, va_list ap);

static vprintf_like_t	s_prev_vprintf = NULL;

static bool		s_inited = false;
static bool		s_stream_enabled = false;
static bool		s_mesh_connected = false;
static portMUX_TYPE	s_state_lock = portMUX_INITIALIZER_UNLOCKED;

static char		s_tag[16] = "node";

static uint32_t		s_cnt = 0;
static TaskHandle_t	s_nodeinfo_task = NULL;
static TaskHandle_t	s_nodeinfo_burst_task = NULL;
static TaskHandle_t	s_log_worker_task = NULL;
static QueueHandle_t	s_log_queue = NULL;
static esp_err_t	s_last_send_err = ESP_OK;
static uint32_t		s_last_tx_ok_ms = 0;
static keemash_mesh_log_stream_stats_t s_log_stats;
static uint32_t		s_reported_overflow = 0;

#ifndef CONFIG_KEEMASH_LOG_CAPTURE_QUEUE_LEN
	#define CONFIG_KEEMASH_LOG_CAPTURE_QUEUE_LEN 32
#endif

#ifndef CONFIG_KEEMASH_LOG_CAPTURE_LINE_MAX
	#define CONFIG_KEEMASH_LOG_CAPTURE_LINE_MAX 256
#endif

#ifndef CONFIG_KEEMASH_NODEINFO_PERIOD_MS
	#define CONFIG_KEEMASH_NODEINFO_PERIOD_MS	15000
#endif

#ifndef CONFIG_KEEMASH_NODE_V2_LOG_ENABLE
	#define CONFIG_KEEMASH_NODE_V2_LOG_ENABLE 1
#endif

static uint32_t now_ms(void)
{
	return (uint32_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);
}

static bool stream_enabled_snapshot(void)
{
	bool enabled;
	portENTER_CRITICAL(&s_state_lock);
	enabled = s_stream_enabled;
	portEXIT_CRITICAL(&s_state_lock);
	return enabled;
}

static bool mesh_connected_snapshot(void)
{
	bool connected;
	portENTER_CRITICAL(&s_state_lock);
	connected = s_mesh_connected;
	portEXIT_CRITICAL(&s_state_lock);
	return connected;
}

typedef struct {
	char line[CONFIG_KEEMASH_LOG_CAPTURE_LINE_MAX];
} log_capture_item_t;

static void build_time_prefix(char *out, size_t out_sz)
{
	if (!out || out_sz == 0) return;

	time_t now = time(NULL);
	if (now <= 0) {
		snprintf(out, out_sz, "[no-time] ");
		return;
	}

	struct tm tm_now;
	if (!localtime_r(&now, &tm_now)) {
		snprintf(out, out_sz, "[no-time] ");
		return;
	}

	size_t n = strftime(out, out_sz, "[%Y-%m-%d %H:%M:%S] ", &tm_now);
	if (n == 0) snprintf(out, out_sz, "[no-time] ");
}

static void record_send_result(esp_err_t err)
{
	uint32_t now = now_ms();
	portENTER_CRITICAL(&s_state_lock);
	s_last_send_err = err;
	if (err == ESP_OK) {
		s_last_tx_ok_ms = now;
	}
	portEXIT_CRITICAL(&s_state_lock);
}

esp_err_t keemash_mesh_log_stream_send_bin_to_root(const void *packet, size_t packet_len)
{
	static uint32_t last_warn_ms = 0;
	if (!packet || packet_len == 0) return ESP_ERR_INVALID_ARG;
	uint32_t now = now_ms();
	if (!mesh_connected_snapshot()) {
		record_send_result(ESP_ERR_INVALID_STATE);
		if (last_warn_ms == 0 || (uint32_t)(now - last_warn_ms) >= 5000U) {
			last_warn_ms = now;
			ESP_LOGW(TAG, "root bin send blocked: mesh not connected len=%u", (unsigned)packet_len);
		}
		return ESP_ERR_INVALID_STATE;
	}

	const uint8_t root[6] = {0};
	esp_err_t err = keemash_mesh_transport_send(root, packet, packet_len);
	record_send_result(err);
	if (err != ESP_OK &&
	    (last_warn_ms == 0 || (uint32_t)(now - last_warn_ms) >= 5000U)) {
		last_warn_ms = now;
		ESP_LOGW(TAG, "root bin send failed len=%u err=%s", (unsigned)packet_len, esp_err_to_name(err));
	}
	return err;
}

bool keemash_mesh_log_stream_transport_ready(void)
{
	return mesh_connected_snapshot();
}

static esp_err_t send_nodeinfo_to_root(void)
{
	if (!mesh_connected_snapshot()) {
		record_send_result(ESP_ERR_INVALID_STATE);
		return ESP_ERR_INVALID_STATE;
	}

	esp_err_t v2_err = mesh_v2_node_send_nodeinfo();
	if (v2_err == ESP_OK) {
		record_send_result(ESP_OK);
		return ESP_OK;
	}
	if (mesh_v2_node_lossless_negotiated()) {
		record_send_result(v2_err);
		return v2_err;
	}
#if !CONFIG_KEEMASH_V1_PRENEGOTIATION_ENABLE
	record_send_result(v2_err);
	return v2_err;
#endif

	mesh_nodeinfo_v2_packet_t p;
	memset(&p, 0, sizeof(p));

	p.h.magic = MESH_PKT_MAGIC;
	p.h.version = MESH_PKT_VERSION;
	p.h.type = MESH_LOG_TYPE_NODEINFO;
	p.h.counter = ++s_cnt;

	keemash_mesh_get_local_mac(p.h.src_mac);
	strncpy(p.tag, s_tag, sizeof(p.tag) - 1);
	p.tag[sizeof(p.tag) - 1] = '\0';
	p.uptime_s = (uint32_t)(esp_timer_get_time() / 1000000ULL);

	// Keep V1 NODEINFO alive as a compatibility beacon. It makes the node
	// visible even while V2 is recovering after a root reboot.
	const uint8_t root[6] = {0};
	esp_err_t err = keemash_mesh_transport_send(root, &p, sizeof(p));
	record_send_result(err);
	return err;
}

static esp_err_t send_logline_to_root(const char *line)
{
	if (!line) return ESP_ERR_INVALID_ARG;
	if (!mesh_connected_snapshot()) {
		record_send_result(ESP_ERR_INVALID_STATE);
		return ESP_ERR_INVALID_STATE;
	}

#if CONFIG_KEEMASH_NODE_V2_LOG_ENABLE
	esp_err_t v2_err = mesh_v2_node_send_log_line(line);
	if (v2_err == ESP_OK) {
		record_send_result(ESP_OK);
		return ESP_OK;
	}
	if (mesh_v2_node_lossless_negotiated()) {
		record_send_result(v2_err);
		return v2_err;
	}
#if !CONFIG_KEEMASH_V1_PRENEGOTIATION_ENABLE
	record_send_result(v2_err);
	return v2_err;
#endif
#else
	mesh_v2_node_kick_root();
#endif

	mesh_log_line_packet_t p;
	memset(&p, 0, sizeof(p));

	p.h.magic = MESH_PKT_MAGIC;
	p.h.version = MESH_PKT_VERSION;
	p.h.type = MESH_LOG_TYPE_LINE;
	p.h.counter = ++s_cnt;

	keemash_mesh_get_local_mac(p.h.src_mac);
	strncpy(p.tag, s_tag, sizeof(p.tag) - 1);
	p.tag[sizeof(p.tag) - 1] = '\0';

	// line already includes time prefix we build here
	strncpy(p.line, line, sizeof(p.line) - 1);
	p.line[sizeof(p.line) - 1] = '\0';

	const uint8_t root[6] = {0};
	esp_err_t err = keemash_mesh_transport_send(root, &p, sizeof(p));
	record_send_result(err);
	return err;
}

static void log_worker_task(void *arg)
{
	(void)arg;
	log_capture_item_t item;

	for (;;) {
		if (xQueueReceive(s_log_queue, &item, portMAX_DELAY) != pdTRUE) continue;
		esp_err_t err;
		do {
			err = send_logline_to_root(item.line);
			if (err != ESP_OK) vTaskDelay(pdMS_TO_TICKS(250));
		} while (err != ESP_OK);

		uint32_t overflow;
		uint32_t pending = uxQueueMessagesWaiting(s_log_queue);
		portENTER_CRITICAL(&s_state_lock);
		s_log_stats.delivered++;
		s_log_stats.pending = pending;
		overflow = s_log_stats.capture_overflow;
		portEXIT_CRITICAL(&s_state_lock);

		if (overflow != s_reported_overflow) {
			char tprefix[40];
			char summary[CONFIG_KEEMASH_LOG_CAPTURE_LINE_MAX];
			build_time_prefix(tprefix, sizeof(tprefix));
			snprintf(summary, sizeof(summary),
			         "%sW (0) mesh_log: capture queue dropped %lu lines",
			         tprefix, (unsigned long)(overflow - s_reported_overflow));
			if (send_logline_to_root(summary) == ESP_OK) {
				s_reported_overflow = overflow;
			}
		}
	}
}

static void capture_log_line(const char *fmt, va_list ap)
{
	if (!s_log_queue || !fmt) return;

	log_capture_item_t item = {0};
	char tprefix[40];
	build_time_prefix(tprefix, sizeof(tprefix));
	size_t prefix_len = strnlen(tprefix, sizeof(tprefix));
	if (prefix_len >= sizeof(item.line)) prefix_len = sizeof(item.line) - 1;
	memcpy(item.line, tprefix, prefix_len);

	va_list copy;
	va_copy(copy, ap);
	(void)vsnprintf(item.line + prefix_len, sizeof(item.line) - prefix_len, fmt, copy);
	va_end(copy);

	if (xQueueSend(s_log_queue, &item, 0) == pdTRUE) {
		uint32_t pending = uxQueueMessagesWaiting(s_log_queue);
		portENTER_CRITICAL(&s_state_lock);
		s_log_stats.captured++;
		s_log_stats.pending = pending;
		if (pending > s_log_stats.high_watermark) s_log_stats.high_watermark = pending;
		portEXIT_CRITICAL(&s_state_lock);
		return;
	}

	portENTER_CRITICAL(&s_state_lock);
	s_log_stats.capture_overflow++;
	portEXIT_CRITICAL(&s_state_lock);
}

static void send_stream_status_to_root(bool enabled)
{
	char tprefix[40];
	char line[96];

	build_time_prefix(tprefix, sizeof(tprefix));
	snprintf(line, sizeof(line),
	         "%sI (0) mesh_log: remote log stream %s",
	         tprefix,
	         enabled ? "ready" : "disabled");
	(void)send_logline_to_root(line);
}

static void nodeinfo_heartbeat_task(void *arg)
{
	(void)arg;

	for (;;) {
		vTaskDelay(pdMS_TO_TICKS(CONFIG_KEEMASH_NODEINFO_PERIOD_MS));
		(void)send_nodeinfo_to_root();
		(void)mesh_v2_node_send_topology();
	}
}

static void nodeinfo_burst_task(void *arg)
{
	(void)arg;

	for (uint32_t i = 0; i < 3; i++) {
		(void)send_nodeinfo_to_root();
		(void)mesh_v2_node_send_topology();
		vTaskDelay(pdMS_TO_TICKS(350));
	}

	portENTER_CRITICAL(&s_state_lock);
	s_nodeinfo_burst_task = NULL;
	portEXIT_CRITICAL(&s_state_lock);
	vTaskDelete(NULL);
}

static int mesh_log_vprintf(const char *fmt, va_list ap)
{
	// 1) Print to UART through the previous sink.
	int ret = 0;
	if (s_prev_vprintf) {
		va_list ap_copy;
		va_copy(ap_copy, ap);
		ret = s_prev_vprintf(fmt, ap_copy);
		va_end(ap_copy);
	}

	// The worker can produce transport diagnostics. Keep those on UART without
	// feeding them back into its own capture queue.
	if (!stream_enabled_snapshot() ||
	    xTaskGetCurrentTaskHandle() == s_log_worker_task) return ret;

	capture_log_line(fmt, ap);
	return ret;
}

esp_err_t keemash_mesh_log_stream_init(const char *tag)
{
	if (s_inited) return ESP_OK;

	if (tag && tag[0]) {
		strncpy(s_tag, tag, sizeof(s_tag) - 1);
		s_tag[sizeof(s_tag) - 1] = '\0';
	}

	if (!s_nodeinfo_task) {
		if (xTaskCreate(nodeinfo_heartbeat_task, "nodeinfo_hb", 4096, NULL, 4,
		                &s_nodeinfo_task) != pdPASS) return ESP_ERR_NO_MEM;
	}
	if (!s_log_queue) {
		s_log_queue = xQueueCreate(CONFIG_KEEMASH_LOG_CAPTURE_QUEUE_LEN,
		                           sizeof(log_capture_item_t));
		if (!s_log_queue) return ESP_ERR_NO_MEM;
	}
	if (!s_log_worker_task &&
	    xTaskCreate(log_worker_task, "mesh_log_tx", 4096, NULL, 4,
	                &s_log_worker_task) != pdPASS) {
		vQueueDelete(s_log_queue);
		s_log_queue = NULL;
		return ESP_ERR_NO_MEM;
	}
	s_prev_vprintf = (vprintf_like_t)esp_log_set_vprintf(&mesh_log_vprintf);
	s_inited = true;
	ESP_LOGI(TAG, "mesh log stream inited (waiting CTRL)");
	return ESP_OK;
}

void keemash_mesh_log_stream_on_mesh_connected(void)
{
	portENTER_CRITICAL(&s_state_lock);
	s_mesh_connected = true;
	portEXIT_CRITICAL(&s_state_lock);
	(void)send_nodeinfo_to_root();
	keemash_mesh_log_stream_kick_nodeinfo_burst();
}

void keemash_mesh_log_stream_on_mesh_disconnected(void)
{
	portENTER_CRITICAL(&s_state_lock);
	s_mesh_connected = false;
	s_stream_enabled = false;
	s_last_tx_ok_ms = 0;
	portEXIT_CRITICAL(&s_state_lock);
}

esp_err_t keemash_mesh_log_stream_send_nodeinfo_now(void)
{
	return send_nodeinfo_to_root();
}

void keemash_mesh_log_stream_kick_nodeinfo_burst(void)
{
	bool should_start = false;

	portENTER_CRITICAL(&s_state_lock);
	if (!s_nodeinfo_burst_task && s_mesh_connected) {
		s_nodeinfo_burst_task = (TaskHandle_t)1;
		should_start = true;
	}
	portEXIT_CRITICAL(&s_state_lock);

	if (!should_start) {
		return;
	}

	TaskHandle_t task = NULL;
	if (xTaskCreate(nodeinfo_burst_task, "nodeinfo_burst", 4096, NULL, 4,
	                &task) == pdPASS) {
		portENTER_CRITICAL(&s_state_lock);
		s_nodeinfo_burst_task = task;
		portEXIT_CRITICAL(&s_state_lock);
	} else {
		portENTER_CRITICAL(&s_state_lock);
		s_nodeinfo_burst_task = NULL;
		portEXIT_CRITICAL(&s_state_lock);
		(void)send_nodeinfo_to_root();
	}
}

esp_err_t keemash_mesh_log_stream_last_send_err(void)
{
	esp_err_t err;
	portENTER_CRITICAL(&s_state_lock);
	err = s_last_send_err;
	portEXIT_CRITICAL(&s_state_lock);
	return err;
}

uint32_t keemash_mesh_log_stream_tx_accepted_age_ms(void)
{
	uint32_t last_tx_ok_ms;
	portENTER_CRITICAL(&s_state_lock);
	last_tx_ok_ms = s_last_tx_ok_ms;
	portEXIT_CRITICAL(&s_state_lock);

	if (last_tx_ok_ms == 0) {
		return UINT32_MAX;
	}
	return (uint32_t)(now_ms() - last_tx_ok_ms);
}

bool keemash_mesh_log_stream_tx_accepted_fresh(uint32_t max_age_ms)
{
	return keemash_mesh_log_stream_tx_accepted_age_ms() <= max_age_ms;
}

void keemash_mesh_log_stream_clear_tx_accepted(void)
{
	portENTER_CRITICAL(&s_state_lock);
	s_last_tx_ok_ms = 0;
	portEXIT_CRITICAL(&s_state_lock);
}

bool keemash_mesh_log_stream_enabled(void)
{
	return stream_enabled_snapshot();
}

void keemash_mesh_log_stream_stats(keemash_mesh_log_stream_stats_t *out)
{
	if (!out) return;
	portENTER_CRITICAL(&s_state_lock);
	*out = s_log_stats;
	portEXIT_CRITICAL(&s_state_lock);
}

esp_err_t keemash_mesh_log_stream_handle_v1_ctrl(const void *pkt_buf, size_t pkt_len)
{
	if (!pkt_buf || pkt_len < sizeof(mesh_log_ctrl_packet_t)) {
		return ESP_ERR_INVALID_SIZE;
	}

	const mesh_log_ctrl_packet_t *p = (const mesh_log_ctrl_packet_t *)pkt_buf;

	if (p->h.magic != MESH_PKT_MAGIC || p->h.version != MESH_PKT_VERSION) {
		return ESP_ERR_INVALID_ARG;
	}
	if (p->h.type != MESH_LOG_TYPE_CTRL) {
		return ESP_ERR_INVALID_ARG;
	}

	bool enable = (p->enable != 0);
	portENTER_CRITICAL(&s_state_lock);
	s_stream_enabled = enable;
	portEXIT_CRITICAL(&s_state_lock);

	if (enable) {
		(void)send_nodeinfo_to_root();
		send_stream_status_to_root(true);
	}

	// Do not log here: this path is reached from the vprintf hook.
	return ESP_OK;
}
