# Node Compatibility Memory Hardening

This patch branches from v0.9.4, without OTA v3 changes. The public API and
reliable V2 wire protocol are unchanged.

When `CONFIG_KEEMASH_V2_COMPAT_TUNNEL_ENABLE=n`, omit the old replay rings,
their receive-channel state and unreachable compatibility handlers. Keep the
reliable V2 engine, ACK/retry state, PING/PONG, typed CONTROL and V1
pre-negotiation beacons. With compatibility enabled, retain the original rings
and handlers.

The baseline ESP32 map allocated 18,920 bytes for `s_tunnel_tx`, 7,552 bytes
for `s_ring` and 120 bytes for `s_tunnel_rx`. The disabled configuration should
therefore recover 26,592 bytes before other diagnostic changes. This is static
memory recovery, not proof that a heap leak or watchdog cause has been fixed.

Validate both configurations with the ESP-IDF compiler and confirm ring symbols
are absent/present respectively. Hardware recovery and sustained-operation
qualification remain consumer-specific gates before wider adoption.
