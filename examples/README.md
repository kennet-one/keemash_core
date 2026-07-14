# Node Runtime Adapter Example

`node_runtime_adapter.c` shows the intentionally small firmware-owned boundary:

- one serialized raw `esp_mesh_send()` callback;
- local STA MAC lookup;
- broker sizing;
- parent-connected/disconnected event binding.

The shared component owns reliability, typed telemetry, log capture, heartbeat,
TIME application, OTA v2 receive logic and packet-priority classification.
Application command hooks, ESP-MESH configuration, recovery policy and hardware
modules remain in the firmware repository.

Copy the structure, not credentials or board-specific mesh configuration.
