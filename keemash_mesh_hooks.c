// SPDX-License-Identifier: Apache-2.0
#include "keemash_mesh_hooks.h"

#include <string.h>

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

void __attribute__((weak)) keemash_mesh_root_on_control(const uint8_t peer[6],
                                                         uint32_t root_session,
                                                         uint32_t node_session,
                                                         uint8_t kind,
                                                         uint32_t command_id,
                                                         uint8_t status,
                                                         const char *text)
{
    (void)peer; (void)root_session; (void)node_session;
    (void)command_id; (void)status;
    if (kind == MESH_V2_CONTROL_EVENT) keemash_mesh_root_on_control_event(text);
}

void __attribute__((weak)) keemash_mesh_root_on_state_changed(void)
{
}

bool __attribute__((weak)) keemash_mesh_node_on_control_command_result(const char *text,
                                                                       uint8_t *status,
                                                                       char *result,
                                                                       size_t result_size)
{
    (void)text; (void)status; (void)result; (void)result_size;
    return false;
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

void __attribute__((weak)) keemash_mesh_node_on_time_sync(
    const mesh_v2_time_payload_t *time_sync)
{
    (void)time_sync;
}
