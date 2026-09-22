# OTA v3 artifact and transport (unreleased)

OTA v3 is under development. The C component verifies signed artifacts,
streams them into an inactive slot with persistent checkpoints, selects a
verified image only after a node safety preflight, and retains a post-boot
attestation until the root acknowledges it. A bounded node worker and root
send/receive facade carry typed OTA messages over reliable mesh. No production
firmware advertises `MESH_V2_CAP_OTA_V3` yet. Do not deploy or flash an OTA v3
image until root orchestration, production trust provisioning and interruption
gates are complete.

## Artifact format

`.kota3` begins with an eight-byte magic (`KOTA3`, two zero bytes, format
version 1), a little-endian 32-bit manifest length and a little-endian CRC32
of the manifest. A protobuf `FirmwareArtifactManifest` follows; the remaining
bytes are the concatenated encoded block payloads. The header CRC detects
accidental corruption but is not an authenticity check.

The P-256/SHA-256 signature covers the exact serialized `signed_fields`
bytes, not a re-encoded protobuf. The signing key is not stored in this
repository. The signed fields include project and chip target, firmware/build
identity, minimum compatibility, image and encoded-payload SHA-256, block
count and sizes, codec, and a signed block-table hash. Full artifacts use
independent 16 KiB raw-DEFLATE blocks with 11-bit window. Delta artifacts are
experimental, use 8 KiB output blocks, and require an exact running-image
hash match; no firmware accepts them unless explicitly configured.

The block-table hash is a 32-byte chain, initially all zero. For each block,
encode its descriptor as a length-delimited protobuf and compute
`SHA256(previous_chain || encoded_descriptor)`. This permits a target to
verify the table incrementally without storing all descriptors. A receiver
must additionally verify each encoded block hash, each raw block hash, the
total encoded-payload hash and the final raw image hash before changing the
boot partition. A valid signature alone does not authorize installation on
the wrong project, chip or slot.

Host parsing is bounded to 16 MiB package, 1 MiB manifest, 8 MiB raw image
and 1024 blocks. The embedded target must check its actual update-slot size
and supported core/Fabric versions. No zero-fill or implicit gaps are allowed
between sequential raw or encoded offsets.

The embedded stream validator accepts at most 2 KiB per chunk. It checks
strict offsets, descriptors, the encoded and raw SHA-256 of every block, the
complete payload and image hashes, and a byte-identical retry of the latest
chunk. Its output callback may write provisional bytes only to an inactive
partition; any validation or callback failure must abort that OTA handle.
The separate flash receiver adds persistent checkpoints and OTA-handle resume;
neither validator nor receiver changes the boot partition or reports post-boot
health. Neither is a deployment path by itself.

The complete-package verifier reads the header and CRC, decodes the manifest
twice using a bounded nanopb flash stream, verifies the P-256 signature and
feeds every encoded block through the streaming validator. It never keeps a
whole image or manifest in RAM. It currently accepts full-deflate packages
only and requires the caller to serialize writes to the source storage.
Its ESP-IDF compile/link probe passes, but real-package and interruption
tests on an ESP target remain required before it can authorize vault commits.

The stream API can restart at a verified block-boundary checkpoint. It
re-reads the raw prefix from the inactive partition to rebuild the final
image hash. The encoded prefix is not present in that partition, so a resumed
stream verifies every remaining encoded block against its signed descriptor
but does not recompute the redundant whole encoded-payload hash. The final
signed image hash and descriptor-chain hash are still mandatory. The receiver
must validate checkpoint metadata and the flash prefix before trusting the
resume offsets; the experimental flash writer does this but is not connected
to production transport.

The embedded checkpoint journal uses alternating NVS blobs with generation
and CRC, and a newer tombstone for cancellation. It writes no checkpoint in
the middle of a block. On load, CRC and structural bounds are only the first
gate: the receiver must re-verify the saved signed fields, operation and
artifact identity, update-slot label, then rehash the inactive flash prefix
before calling `esp_ota_resume()`. The experimental flash writer now uses
this journal, but no production firmware calls the writer yet.

The flash writer implements signed prepare, sequential block writes, verified
checkpoint/resume, complete image validation with `esp_ota_end()` and an
explicit activation step. Activation reruns the caller-supplied safety
preflight, persists `BOOT_PENDING` and selects the verified partition; the
worker sends a reliable status before it reboots. After boot, a report derives
`PENDING`, `VALIDATED`, `ROLLED_BACK` or `FAILED` from the journal, running
partition and ESP-IDF rollback state. The report remains pending until an exact
operation/artifact/state acknowledgement clears it.

Committed vault artifacts can be inspected through bounded authenticated
metadata and block-iterator APIs without inflating the image a second time.
Targets still verify each block and the final image. Root orchestration,
production trust provisioning and hardware interruption tests remain required
before rollout.

## Signing key handling

Use a dedicated offline P-256 key. `kota3 keygen` requires absolute paths,
refuses overwrites and refuses to place the private key under a Git repository.
The public SEC1 key is configured in firmware. The private key must remain
offline and must never be copied into firmware, desktop builds, Git or CI logs.
Test vectors use a deterministic non-production key and must not be trusted
by released firmware.

## Migration boundary

OTA v2 remains only the bootstrap route while a node lacks the v3 capability.
After every active core-backed node has completed and validated a real OTA v3
update, production v2 routing and advertisement are removed; it is not a
permanent silent fallback. The root partition migration preserves the existing
`ota_0` and `ota_1` offsets and sizes; USB flashing is required once to install
the new partition table. An artifact being staged is not an applied deployment.
The desktop must require an explicit plan/apply action, and the root must report
success only after the expected post-boot image is validated. Missing
validation is `outcome_unknown`, not success.
