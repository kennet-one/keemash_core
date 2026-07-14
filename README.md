# keemash_mesh_core

Shared ESP-IDF component for the KeeMASH reliable V2 application layer over
ESP-MESH.

Repository: `kennet-one/keemash_core`.

Current version: `0.5.0`.

License: `GPL-2.0-only`.

## Scope

- root/node boot sessions;
- per-channel sequence spaces;
- cumulative ACK and 32-bit SACK;
- reorder buffering and in-order delivery;
- adaptive RTO and timeout retransmission;
- explicit LOST ranges;
- fragmentation/reassembly up to 16 fragments;
- channel priorities and reserved CONTROL slots;
- deterministic fault injection;
- typed reliable OTA payloads on the reserved OTA channel;
- serialized priority TX broker with explicit queue ownership;
- route-aware retry pause/resume with bounded grace and explicit route loss;
- transport-origin validation for authenticated root/node traffic;
- latest-wins typed TIME delivery without stale timestamp replay;
- reusable root and node facades with ESP-MESH transport hooks;
- generic task, memory, OTA slot and OTA v2 receiver helpers.
- reusable node log capture, NODEINFO heartbeat and recovery burst runtime;
- reusable V1/V2 time-application helper;
- reusable timestamped UART log hook;
- automatic TX broker packet-priority classification.

ESP-MESH remains responsible for multi-hop routing. The core provides end-to-end
reliability between a node and root; it does not add an application hop-by-hop
router. Manual reboot is a typed CONTROL command, time sync uses a typed
latest-wins channel, and OTA uses the reliable layer only when firmware
explicitly advertises `MESH_V2_CAP_OTA`.

## Integration

Firmware projects add this component to ESP-IDF Component Manager or `EXTRA_COMPONENT_DIRS`, require
`keemash_mesh_core`, and keep only their transport binding, web/legacy glue,
node-specific recovery policy, command adapter and hardware modules. Firmware provides
strong hook implementations declared in `keemash_mesh_hooks.h`.

Consumers must verify `KEEMASH_MESH_CORE_VERSION`. The current firmware pin is:

```c
#if KEEMASH_MESH_CORE_VERSION != 0x00050000UL
#error "firmware requires keemash_mesh_core 0.5.0"
#endif
```

Use a fixed commit or tag such as `v0.5.0` when integrating the component into
node firmware repositories.

## Production Defaults

- initial RTO: `1500 ms`;
- RTO range: `500-5000 ms`;
- maximum retransmissions: `5`;
- fragment timeout: `10 s`;
- every fault-injection counter: `0`.

Fault injection must be returned to zero before a production image is flashed.

## Firmware Binding Notes

Firmware must provide strong keemash_mesh_transport_send() and keemash_mesh_get_local_mac() implementations from its ESP-MESH transport adapter. These hooks are intentionally not weak defaults: a missing transport binding must fail at link time instead of producing a runtime ESP_ERR_INVALID_STATE handshake failure.
