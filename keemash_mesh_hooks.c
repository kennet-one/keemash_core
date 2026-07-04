// SPDX-License-Identifier: GPL-2.0-only
#include "keemash_mesh_hooks.h"

#include <string.h>

esp_err_t __attribute__((weak)) keemash_mesh_transport_send(const uint8_t dst[6],
                                                            const void *packet,
                                                            size_t packet_len)
{
    (void)dst;
    (void)packet;
    (void)packet_len;
    return ESP_ERR_INVALID_STATE;
}

void __attribute__((weak)) keemash_mesh_get_local_mac(uint8_t mac[6])
{
    if (mac) memset(mac, 0, 6);
}

void __attribute__((weak)) keemash_mesh_root_on_node_seen_uptime(const uint8_t mac[6],
                                                                 const char *tag,
                                                                 bool uptime_valid,
                                                                 uint32_t uptime_s)
{
    (void)mac; (void)tag; (void)uptime_valid; (void)uptime_s;
}

void __attribute__((weak)) keemash_mesh_root_on_node_seen(const uint8_t mac[6], const char *tag)
{
    (void)mac; (void)tag;
}

void __attribute__((weak)) keemash_mesh_root_on_log_line(const uint8_t mac[6],
                                                         const char *tag,
                                                         const char *line)
{
    (void)mac; (void)tag; (void)line;
}

void __attribute__((weak)) keemash_mesh_root_on_task_snapshot(const uint8_t mac[6],
                                                              const mesh_v2_task_snapshot_payload_t *snapshot)
{
    (void)mac; (void)snapshot;
}

void __attribute__((weak)) keemash_mesh_root_on_memory_snapshot(const uint8_t mac[6],
                                                                const mesh_v2_memory_payload_t *snapshot)
{
    (void)mac; (void)snapshot;
}

void __attribute__((weak)) keemash_mesh_root_on_ota_status(const uint8_t mac[6],
                                                           const mesh_v2_ota_status_payload_t *status,
                                                           size_t status_len)
{
    (void)mac; (void)status; (void)status_len;
}

void __attribute__((weak)) keemash_mesh_root_on_topology(const uint8_t mac[6],
                                                         const void *payload,
                                                         size_t payload_len)
{
    (void)mac; (void)payload; (void)payload_len;
}

void __attribute__((weak)) keemash_mesh_root_on_control_event(const char *text)
{
    (void)text;
}

void __attribute__((weak)) keemash_mesh_root_on_state_changed(void)
{
}

bool __attribute__((weak)) keemash_mesh_node_on_control_command(const char *text)
{
    (void)text;
    return false;
}

void __attribute__((weak)) keemash_mesh_node_on_log_ctrl(bool enable)
{
    (void)enable;
}

uint32_t __attribute__((weak)) keemash_mesh_node_v1_ok_age_ms(void)
{
    return UINT32_MAX;
}

bool __attribute__((weak)) keemash_mesh_node_log_stream_enabled(void)
{
    return false;
}
