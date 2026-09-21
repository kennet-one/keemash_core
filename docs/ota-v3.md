# OTA v3 artifact and transport (unreleased)

OTA v3 is under development. The current C component verifies signed manifest
fields, and the Rust crate can package and verify full artifacts. No firmware
advertises `MESH_V2_CAP_OTA_V3` yet. Do not deploy or flash an OTA v3 image
until the receiver, root vault, boot report and rollback gates are complete.

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

## Signing key handling

Use a dedicated offline P-256 key. `kota3 keygen` requires absolute paths,
refuses overwrites and refuses to place the private key under a Git repository.
The public SEC1 key is configured in firmware. The private key must remain
offline and must never be copied into firmware, desktop builds, Git or CI logs.
Test vectors use a deterministic non-production key and must not be trusted
by released firmware.

## Migration boundary

OTA v2 remains the bootstrap route. The root partition migration preserves
the existing `ota_0` and `ota_1` offsets and sizes; USB flashing is required
once to install the new partition table. An artifact being staged is not an
applied deployment. The desktop must require an explicit plan/apply action,
and the root must report success only after the expected post-boot image is
validated. Missing validation is `outcome_unknown`, not success.
