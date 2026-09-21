// SPDX-License-Identifier: GPL-2.0-only

use crate::fabric;
use crc32fast::Hasher as Crc32;
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use prost::Message;
use sha2::{Digest, Sha256};

pub const KOTA3_MAGIC: &[u8; 8] = b"KOTA3\0\0\x01";
pub const KOTA3_HEADER_SIZE: usize = 16;
pub const KOTA3_SCHEMA_VERSION: u32 = 1;
pub const KOTA3_FULL_BLOCK_SIZE: usize = 16 * 1024;
pub const KOTA3_DELTA_BLOCK_SIZE: usize = 8 * 1024;
pub const KOTA3_DEFLATE_WINDOW_BITS: u8 = 11;
pub const KOTA3_SHA256_LEN: usize = 32;
pub const KOTA3_SIGNATURE_LEN: usize = 64;
pub const KOTA3_MAX_PACKAGE_SIZE: usize = 16 * 1024 * 1024;
pub const KOTA3_MAX_IMAGE_SIZE: usize = 8 * 1024 * 1024;
pub const KOTA3_MAX_MANIFEST_SIZE: usize = 1024 * 1024;
pub const KOTA3_MAX_BLOCK_COUNT: usize = 1024;

#[derive(Debug, Clone)]
pub struct ArtifactBuildSpec<'a> {
    pub project_name: &'a str,
    pub chip_target: &'a str,
    pub firmware_version: &'a str,
    pub build_commit: &'a str,
    pub minimum_core_version: u32,
    pub minimum_fabric_schema: u32,
    pub required_app_slot_size: u32,
    pub signing_key_id: &'a str,
}

#[derive(Debug, Clone)]
pub struct VerifiedArtifact {
    pub artifact_id: [u8; KOTA3_SHA256_LEN],
    pub manifest: fabric::FirmwareArtifactManifest,
    pub signed: fabric::FirmwareArtifactSignedFields,
    pub image: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct ArtifactTarget<'a> {
    pub project_name: &'a str,
    pub chip_target: &'a str,
    pub app_slot_size: u32,
    pub core_version: u32,
    pub fabric_schema: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactError {
    TooShort,
    InvalidMagic,
    InvalidManifestLength,
    ManifestCrc,
    Protobuf(String),
    InvalidField(&'static str),
    UnsupportedCodec,
    Signature,
    BlockTableHash,
    EncodedHash,
    ImageHash,
    BlockHash(u32),
    BlockBounds(u32),
    Deflate(u32),
    MissingBaseImage,
    WrongBaseImage,
    SizeOverflow,
    IncompatibleTarget(&'static str),
}

impl std::fmt::Display for ArtifactError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => formatter.write_str("OTA artifact is too short"),
            Self::InvalidMagic => formatter.write_str("invalid OTA v3 artifact magic"),
            Self::InvalidManifestLength => formatter.write_str("invalid OTA manifest length"),
            Self::ManifestCrc => formatter.write_str("OTA manifest CRC mismatch"),
            Self::Protobuf(message) => write!(formatter, "invalid OTA protobuf: {message}"),
            Self::InvalidField(field) => write!(formatter, "invalid OTA field: {field}"),
            Self::UnsupportedCodec => formatter.write_str("unsupported OTA artifact codec"),
            Self::Signature => formatter.write_str("OTA artifact signature verification failed"),
            Self::BlockTableHash => formatter.write_str("OTA block table hash mismatch"),
            Self::EncodedHash => formatter.write_str("OTA encoded payload hash mismatch"),
            Self::ImageHash => formatter.write_str("OTA image hash mismatch"),
            Self::BlockHash(index) => write!(formatter, "OTA block {index} hash mismatch"),
            Self::BlockBounds(index) => write!(formatter, "OTA block {index} is out of bounds"),
            Self::Deflate(index) => write!(formatter, "OTA block {index} decompression failed"),
            Self::MissingBaseImage => formatter.write_str("delta artifact requires a base image"),
            Self::WrongBaseImage => formatter.write_str("delta artifact base image hash mismatch"),
            Self::SizeOverflow => formatter.write_str("OTA artifact size exceeds 32-bit limits"),
            Self::IncompatibleTarget(field) => write!(formatter, "OTA target mismatch: {field}"),
        }
    }
}

impl std::error::Error for ArtifactError {}

fn sha256(data: &[u8]) -> [u8; KOTA3_SHA256_LEN] {
    Sha256::digest(data).into()
}

fn checked_u32(value: usize) -> Result<u32, ArtifactError> {
    u32::try_from(value).map_err(|_| ArtifactError::SizeOverflow)
}

fn bytes32(value: &[u8], field: &'static str) -> Result<[u8; 32], ArtifactError> {
    value
        .try_into()
        .map_err(|_| ArtifactError::InvalidField(field))
}

fn encode_block_descriptor(block: &fabric::FirmwareBlockDescriptor) -> Vec<u8> {
    let mut encoded = Vec::new();
    block
        .encode_length_delimited(&mut encoded)
        .expect("encoding a block descriptor into Vec cannot fail");
    encoded
}

fn block_table_chain(blocks: &[fabric::FirmwareBlockDescriptor]) -> [u8; 32] {
    let mut chain = [0_u8; 32];
    for block in blocks {
        let descriptor = encode_block_descriptor(block);
        let mut hasher = Sha256::new();
        hasher.update(chain);
        hasher.update(descriptor);
        chain = hasher.finalize().into();
    }
    chain
}

fn compress_block(raw: &[u8]) -> Result<Vec<u8>, ArtifactError> {
    let mut compressor =
        Compress::new_with_window_bits(Compression::best(), false, KOTA3_DEFLATE_WINDOW_BITS);
    let mut encoded = vec![0_u8; raw.len().saturating_mul(2).saturating_add(256)];
    let status = compressor
        .compress(raw, &mut encoded, FlushCompress::Finish)
        .map_err(|_| ArtifactError::Deflate(0))?;
    if status != Status::StreamEnd {
        return Err(ArtifactError::Deflate(0));
    }
    encoded.truncate(compressor.total_out() as usize);
    Ok(encoded)
}

fn decompress_block(
    encoded: &[u8],
    expected_size: usize,
    index: u32,
) -> Result<Vec<u8>, ArtifactError> {
    let mut decompressor = Decompress::new_with_window_bits(false, KOTA3_DEFLATE_WINDOW_BITS);
    let mut raw = vec![0_u8; expected_size];
    let status = decompressor
        .decompress(encoded, &mut raw, FlushDecompress::Finish)
        .map_err(|_| ArtifactError::Deflate(index))?;
    if status != Status::StreamEnd
        || decompressor.total_out() as usize != expected_size
        || decompressor.total_in() as usize != encoded.len()
    {
        return Err(ArtifactError::Deflate(index));
    }
    Ok(raw)
}

pub fn build_full_artifact(
    image: &[u8],
    spec: &ArtifactBuildSpec<'_>,
    signing_key: &SigningKey,
) -> Result<Vec<u8>, ArtifactError> {
    build_artifact(image, None, spec, signing_key)
}

pub fn build_delta_artifact(
    image: &[u8],
    base_image: &[u8],
    spec: &ArtifactBuildSpec<'_>,
    signing_key: &SigningKey,
) -> Result<Vec<u8>, ArtifactError> {
    if base_image.is_empty() || base_image.len() > KOTA3_MAX_IMAGE_SIZE {
        return Err(ArtifactError::WrongBaseImage);
    }
    build_artifact(image, Some(base_image), spec, signing_key)
}

pub fn verify_for_target(
    artifact: &[u8],
    verifying_key: &VerifyingKey,
    base_image: Option<&[u8]>,
    target: &ArtifactTarget<'_>,
) -> Result<VerifiedArtifact, ArtifactError> {
    let verified = verify_artifact(artifact, verifying_key, base_image)?;
    let signed = &verified.signed;
    if signed.project_name != target.project_name {
        return Err(ArtifactError::IncompatibleTarget("project"));
    }
    if signed.chip_target != target.chip_target {
        return Err(ArtifactError::IncompatibleTarget("chip"));
    }
    if signed.raw_size > target.app_slot_size
        || signed.required_app_slot_size > target.app_slot_size
    {
        return Err(ArtifactError::IncompatibleTarget("app slot"));
    }
    if signed.minimum_core_version > target.core_version {
        return Err(ArtifactError::IncompatibleTarget("core version"));
    }
    if signed.minimum_fabric_schema > target.fabric_schema {
        return Err(ArtifactError::IncompatibleTarget("Fabric schema"));
    }
    Ok(verified)
}

fn build_artifact(
    image: &[u8],
    base_image: Option<&[u8]>,
    spec: &ArtifactBuildSpec<'_>,
    signing_key: &SigningKey,
) -> Result<Vec<u8>, ArtifactError> {
    if image.is_empty() || image.len() > KOTA3_MAX_IMAGE_SIZE {
        return Err(ArtifactError::InvalidField("image"));
    }
    if spec.project_name.is_empty()
        || spec.chip_target.is_empty()
        || spec.firmware_version.is_empty()
        || spec.signing_key_id.is_empty()
    {
        return Err(ArtifactError::InvalidField("artifact identity"));
    }
    if spec.required_app_slot_size < image.len() as u32 {
        return Err(ArtifactError::InvalidField("required_app_slot_size"));
    }

    let mut blocks = Vec::new();
    let mut payload = Vec::new();
    let block_size = if base_image.is_some() {
        KOTA3_DELTA_BLOCK_SIZE
    } else {
        KOTA3_FULL_BLOCK_SIZE
    };
    for (index, raw) in image.chunks(block_size).enumerate() {
        let raw_offset = index * block_size;
        let can_copy = base_image
            .is_some_and(|base| base.get(raw_offset..raw_offset + raw.len()) == Some(raw));
        let encoded = if can_copy {
            Vec::new()
        } else {
            compress_block(raw)?
        };
        let descriptor = fabric::FirmwareBlockDescriptor {
            index: checked_u32(index)?,
            raw_offset: checked_u32(raw_offset)?,
            raw_size: checked_u32(raw.len())?,
            encoded_offset: checked_u32(payload.len())?,
            encoded_size: checked_u32(encoded.len())?,
            kind: if can_copy {
                fabric::FirmwareBlockKind::FirmwareBlockCopyBase as i32
            } else {
                fabric::FirmwareBlockKind::FirmwareBlockDeflate as i32
            },
            raw_sha256: sha256(raw).to_vec(),
            encoded_sha256: sha256(&encoded).to_vec(),
        };
        payload.extend_from_slice(&encoded);
        blocks.push(descriptor);
    }

    let signed = fabric::FirmwareArtifactSignedFields {
        schema_version: KOTA3_SCHEMA_VERSION,
        project_name: spec.project_name.to_owned(),
        chip_target: spec.chip_target.to_owned(),
        firmware_version: spec.firmware_version.to_owned(),
        build_commit: spec.build_commit.to_owned(),
        minimum_core_version: spec.minimum_core_version,
        minimum_fabric_schema: spec.minimum_fabric_schema,
        raw_size: checked_u32(image.len())?,
        encoded_size: checked_u32(payload.len())?,
        required_app_slot_size: spec.required_app_slot_size,
        codec: if base_image.is_some() {
            fabric::FirmwareArtifactCodec::ArtifactCodecDeltaBlock as i32
        } else {
            fabric::FirmwareArtifactCodec::ArtifactCodecFullDeflate as i32
        },
        image_sha256: sha256(image).to_vec(),
        encoded_sha256: sha256(&payload).to_vec(),
        block_table_sha256: block_table_chain(&blocks).to_vec(),
        base_image_sha256: base_image.map_or_else(Vec::new, |base| sha256(base).to_vec()),
        block_size: block_size as u32,
        block_count: checked_u32(blocks.len())?,
        deflate_window_bits: KOTA3_DEFLATE_WINDOW_BITS as u32,
        signing_key_id: spec.signing_key_id.to_owned(),
    };
    let signed_fields = signed.encode_to_vec();
    let signature: Signature = signing_key.sign(&signed_fields);
    let manifest = fabric::FirmwareArtifactManifest {
        signed_fields,
        blocks,
        signature: signature.to_bytes().to_vec(),
    };
    let manifest_bytes = manifest.encode_to_vec();
    if manifest_bytes.len() > KOTA3_MAX_MANIFEST_SIZE {
        return Err(ArtifactError::InvalidManifestLength);
    }
    let manifest_len = checked_u32(manifest_bytes.len())?;
    let mut crc = Crc32::new();
    crc.update(&manifest_bytes);

    let mut artifact = Vec::with_capacity(KOTA3_HEADER_SIZE + manifest_bytes.len() + payload.len());
    artifact.extend_from_slice(KOTA3_MAGIC);
    artifact.extend_from_slice(&manifest_len.to_le_bytes());
    artifact.extend_from_slice(&crc.finalize().to_le_bytes());
    artifact.extend_from_slice(&manifest_bytes);
    artifact.extend_from_slice(&payload);
    if artifact.len() > KOTA3_MAX_PACKAGE_SIZE {
        return Err(ArtifactError::SizeOverflow);
    }
    Ok(artifact)
}

pub fn parse_artifact(
    artifact: &[u8],
) -> Result<
    (
        fabric::FirmwareArtifactManifest,
        fabric::FirmwareArtifactSignedFields,
        &[u8],
    ),
    ArtifactError,
> {
    if artifact.len() < KOTA3_HEADER_SIZE {
        return Err(ArtifactError::TooShort);
    }
    if artifact.len() > KOTA3_MAX_PACKAGE_SIZE {
        return Err(ArtifactError::SizeOverflow);
    }
    if &artifact[..KOTA3_MAGIC.len()] != KOTA3_MAGIC {
        return Err(ArtifactError::InvalidMagic);
    }
    let manifest_len = u32::from_le_bytes(artifact[8..12].try_into().unwrap()) as usize;
    if manifest_len == 0 || manifest_len > KOTA3_MAX_MANIFEST_SIZE {
        return Err(ArtifactError::InvalidManifestLength);
    }
    let manifest_end = KOTA3_HEADER_SIZE
        .checked_add(manifest_len)
        .filter(|end| *end <= artifact.len())
        .ok_or(ArtifactError::InvalidManifestLength)?;
    let expected_crc = u32::from_le_bytes(artifact[12..16].try_into().unwrap());
    let manifest_bytes = &artifact[KOTA3_HEADER_SIZE..manifest_end];
    let mut crc = Crc32::new();
    crc.update(manifest_bytes);
    if crc.finalize() != expected_crc {
        return Err(ArtifactError::ManifestCrc);
    }
    let manifest = fabric::FirmwareArtifactManifest::decode(manifest_bytes)
        .map_err(|error| ArtifactError::Protobuf(error.to_string()))?;
    let signed = fabric::FirmwareArtifactSignedFields::decode(manifest.signed_fields.as_slice())
        .map_err(|error| ArtifactError::Protobuf(error.to_string()))?;
    Ok((manifest, signed, &artifact[manifest_end..]))
}

pub fn verify_artifact(
    artifact: &[u8],
    verifying_key: &VerifyingKey,
    base_image: Option<&[u8]>,
) -> Result<VerifiedArtifact, ArtifactError> {
    let (manifest, signed, payload) = parse_artifact(artifact)?;
    if signed.schema_version != KOTA3_SCHEMA_VERSION {
        return Err(ArtifactError::InvalidField("schema_version"));
    }
    if manifest.signature.len() != KOTA3_SIGNATURE_LEN {
        return Err(ArtifactError::InvalidField("signature"));
    }
    let signature =
        Signature::from_slice(&manifest.signature).map_err(|_| ArtifactError::Signature)?;
    verifying_key
        .verify(&manifest.signed_fields, &signature)
        .map_err(|_| ArtifactError::Signature)?;
    if signed.block_count as usize != manifest.blocks.len()
        || manifest.blocks.is_empty()
        || manifest.blocks.len() > KOTA3_MAX_BLOCK_COUNT
        || signed.raw_size == 0
        || signed.raw_size as usize > KOTA3_MAX_IMAGE_SIZE
        || signed.encoded_size as usize != payload.len()
        || signed.deflate_window_bits != KOTA3_DEFLATE_WINDOW_BITS as u32
        || signed.required_app_slot_size < signed.raw_size
        || signed.project_name.is_empty()
        || signed.chip_target.is_empty()
        || signed.signing_key_id.is_empty()
    {
        return Err(ArtifactError::InvalidField("artifact sizes"));
    }
    if block_table_chain(&manifest.blocks)
        != bytes32(&signed.block_table_sha256, "block_table_sha256")?
    {
        return Err(ArtifactError::BlockTableHash);
    }
    if sha256(payload) != bytes32(&signed.encoded_sha256, "encoded_sha256")? {
        return Err(ArtifactError::EncodedHash);
    }

    let codec = fabric::FirmwareArtifactCodec::try_from(signed.codec)
        .map_err(|_| ArtifactError::UnsupportedCodec)?;
    let expected_block_size = match codec {
        fabric::FirmwareArtifactCodec::ArtifactCodecFullDeflate => KOTA3_FULL_BLOCK_SIZE,
        fabric::FirmwareArtifactCodec::ArtifactCodecDeltaBlock => KOTA3_DELTA_BLOCK_SIZE,
        _ => return Err(ArtifactError::UnsupportedCodec),
    };
    if signed.block_size as usize != expected_block_size {
        return Err(ArtifactError::InvalidField("block_size"));
    }
    if codec == fabric::FirmwareArtifactCodec::ArtifactCodecFullDeflate
        && !signed.base_image_sha256.is_empty()
    {
        return Err(ArtifactError::InvalidField("base_image_sha256"));
    }
    let base = if codec == fabric::FirmwareArtifactCodec::ArtifactCodecDeltaBlock {
        let base = base_image.ok_or(ArtifactError::MissingBaseImage)?;
        if sha256(base) != bytes32(&signed.base_image_sha256, "base_image_sha256")? {
            return Err(ArtifactError::WrongBaseImage);
        }
        Some(base)
    } else {
        None
    };

    let mut image = vec![0_u8; signed.raw_size as usize];
    let mut next_raw = 0_usize;
    let mut next_encoded = 0_usize;
    for (expected_index, block) in manifest.blocks.iter().enumerate() {
        if block.index as usize != expected_index
            || block.raw_offset as usize != next_raw
            || block.encoded_offset as usize != next_encoded
            || block.raw_size == 0
            || block.raw_size as usize > expected_block_size
            || (expected_index + 1 < manifest.blocks.len()
                && block.raw_size as usize != expected_block_size)
        {
            return Err(ArtifactError::BlockBounds(block.index));
        }
        let raw_end = next_raw
            .checked_add(block.raw_size as usize)
            .filter(|end| *end <= image.len())
            .ok_or(ArtifactError::BlockBounds(block.index))?;
        let encoded_end = next_encoded
            .checked_add(block.encoded_size as usize)
            .filter(|end| *end <= payload.len())
            .ok_or(ArtifactError::BlockBounds(block.index))?;
        let encoded = &payload[next_encoded..encoded_end];
        if sha256(encoded) != bytes32(&block.encoded_sha256, "block encoded sha256")? {
            return Err(ArtifactError::BlockHash(block.index));
        }
        let kind = fabric::FirmwareBlockKind::try_from(block.kind)
            .map_err(|_| ArtifactError::UnsupportedCodec)?;
        let raw = match kind {
            fabric::FirmwareBlockKind::FirmwareBlockDeflate => {
                if encoded.is_empty() {
                    return Err(ArtifactError::BlockBounds(block.index));
                }
                decompress_block(encoded, block.raw_size as usize, block.index)?
            }
            fabric::FirmwareBlockKind::FirmwareBlockCopyBase => {
                if codec != fabric::FirmwareArtifactCodec::ArtifactCodecDeltaBlock
                    || !encoded.is_empty()
                    || base.is_none_or(|value| raw_end > value.len())
                {
                    return Err(ArtifactError::BlockBounds(block.index));
                }
                base.ok_or(ArtifactError::MissingBaseImage)?[next_raw..raw_end].to_vec()
            }
            _ => return Err(ArtifactError::UnsupportedCodec),
        };
        if sha256(&raw) != bytes32(&block.raw_sha256, "block raw sha256")? {
            return Err(ArtifactError::BlockHash(block.index));
        }
        image[next_raw..raw_end].copy_from_slice(&raw);
        next_raw = raw_end;
        next_encoded = encoded_end;
    }
    if next_raw != image.len() || next_encoded != payload.len() {
        return Err(ArtifactError::InvalidField("block coverage"));
    }
    if sha256(&image) != bytes32(&signed.image_sha256, "image_sha256")? {
        return Err(ArtifactError::ImageHash);
    }
    Ok(VerifiedArtifact {
        artifact_id: sha256(artifact),
        manifest,
        signed,
        image,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signing_key() -> SigningKey {
        SigningKey::from_slice(&[7_u8; 32]).unwrap()
    }

    fn spec() -> ArtifactBuildSpec<'static> {
        ArtifactBuildSpec {
            project_name: "kPowerLed",
            chip_target: "esp32c6",
            firmware_version: "test-1",
            build_commit: "0123456789abcdef",
            minimum_core_version: 0x000a0000,
            minimum_fabric_schema: 2,
            required_app_slot_size: 0x1a9000,
            signing_key_id: "test-key",
        }
    }

    #[test]
    fn signed_full_artifact_round_trips_multiple_blocks() {
        let image: Vec<u8> = (0..50_000)
            .map(|index| ((index * 31) & 0xff) as u8)
            .collect();
        let key = signing_key();
        let artifact = build_full_artifact(&image, &spec(), &key).unwrap();
        let verified = verify_artifact(&artifact, key.verifying_key(), None).unwrap();
        assert_eq!(verified.image, image);
        assert_eq!(verified.signed.block_count, 4);
        assert_eq!(verified.signed.deflate_window_bits, 11);
        assert_eq!(verified.artifact_id, sha256(&artifact));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let key = signing_key();
        let mut artifact = build_full_artifact(&vec![0x55; 20_000], &spec(), &key).unwrap();
        let manifest_len = u32::from_le_bytes(artifact[8..12].try_into().unwrap()) as usize;
        let manifest_end = KOTA3_HEADER_SIZE + manifest_len;
        artifact[manifest_end - 1] ^= 0x80;
        let manifest = &artifact[KOTA3_HEADER_SIZE..manifest_end];
        let mut crc = Crc32::new();
        crc.update(manifest);
        artifact[12..16].copy_from_slice(&crc.finalize().to_le_bytes());
        assert!(matches!(
            verify_artifact(&artifact, key.verifying_key(), None),
            Err(ArtifactError::Signature) | Err(ArtifactError::Protobuf(_))
        ));
    }

    #[test]
    fn wrong_trusted_key_is_rejected() {
        let key = signing_key();
        let wrong_key = SigningKey::from_slice(&[8_u8; 32]).unwrap();
        let artifact = build_full_artifact(&vec![0x55; 4096], &spec(), &key).unwrap();
        assert_eq!(
            verify_artifact(&artifact, wrong_key.verifying_key(), None).unwrap_err(),
            ArtifactError::Signature
        );
    }

    #[test]
    fn descriptor_tampering_fails_signed_table_check() {
        let key = signing_key();
        let mut artifact = build_full_artifact(&vec![0x66; 20_000], &spec(), &key).unwrap();
        let (mut manifest, _, payload) = parse_artifact(&artifact).unwrap();
        let encoded = payload.to_vec();
        manifest.blocks[0].raw_sha256[0] ^= 1;
        let manifest_bytes = manifest.encode_to_vec();
        let mut crc = Crc32::new();
        crc.update(&manifest_bytes);
        artifact.truncate(KOTA3_HEADER_SIZE);
        artifact[8..12].copy_from_slice(&(manifest_bytes.len() as u32).to_le_bytes());
        artifact[12..16].copy_from_slice(&crc.finalize().to_le_bytes());
        artifact.extend_from_slice(&manifest_bytes);
        artifact.extend_from_slice(&encoded);
        assert_eq!(
            verify_artifact(&artifact, key.verifying_key(), None).unwrap_err(),
            ArtifactError::BlockTableHash
        );
    }

    #[test]
    fn corrupted_payload_is_rejected_before_image_use() {
        let key = signing_key();
        let mut artifact = build_full_artifact(&vec![0x33; 20_000], &spec(), &key).unwrap();
        *artifact.last_mut().unwrap() ^= 1;
        assert!(matches!(
            verify_artifact(&artifact, key.verifying_key(), None),
            Err(ArtifactError::EncodedHash)
        ));
    }

    #[test]
    fn experimental_delta_copies_only_identical_blocks() {
        let key = signing_key();
        let base = vec![0x33; KOTA3_DELTA_BLOCK_SIZE * 3];
        let mut image = base.clone();
        image[KOTA3_DELTA_BLOCK_SIZE + 17] = 0x55;
        let artifact = build_delta_artifact(&image, &base, &spec(), &key).unwrap();
        let verified = verify_artifact(&artifact, key.verifying_key(), Some(&base)).unwrap();
        assert_eq!(verified.image, image);
        assert_eq!(
            verified.manifest.blocks[0].kind,
            fabric::FirmwareBlockKind::FirmwareBlockCopyBase as i32
        );
        assert_eq!(
            verified.manifest.blocks[1].kind,
            fabric::FirmwareBlockKind::FirmwareBlockDeflate as i32
        );
        assert!(matches!(
            verify_artifact(&artifact, key.verifying_key(), Some(&image)),
            Err(ArtifactError::WrongBaseImage)
        ));
    }

    #[test]
    fn signed_artifact_is_bound_to_project_chip_and_slot() {
        let key = signing_key();
        let artifact = build_full_artifact(&vec![0x55; 4096], &spec(), &key).unwrap();
        let target = ArtifactTarget {
            project_name: "kPowerLed",
            chip_target: "esp32c6",
            app_slot_size: spec().required_app_slot_size,
            core_version: spec().minimum_core_version,
            fabric_schema: spec().minimum_fabric_schema,
        };
        assert!(verify_for_target(&artifact, key.verifying_key(), None, &target).is_ok());
        for (changed, expected) in [
            (
                ArtifactTarget {
                    project_name: "lampk",
                    ..target
                },
                "project",
            ),
            (
                ArtifactTarget {
                    chip_target: "esp32s3",
                    ..target
                },
                "chip",
            ),
            (
                ArtifactTarget {
                    app_slot_size: 2048,
                    ..target
                },
                "app slot",
            ),
            (
                ArtifactTarget {
                    core_version: 0,
                    ..target
                },
                "core version",
            ),
            (
                ArtifactTarget {
                    fabric_schema: 0,
                    ..target
                },
                "Fabric schema",
            ),
        ] {
            assert_eq!(
                verify_for_target(&artifact, key.verifying_key(), None, &changed).unwrap_err(),
                ArtifactError::IncompatibleTarget(expected)
            );
        }
    }

    #[test]
    fn all_copy_delta_has_no_encoded_payload() {
        let key = signing_key();
        let base = vec![0x25; KOTA3_DELTA_BLOCK_SIZE];
        let artifact = build_delta_artifact(&base, &base, &spec(), &key).unwrap();
        let verified = verify_artifact(&artifact, key.verifying_key(), Some(&base)).unwrap();
        assert_eq!(verified.image, base);
        assert_eq!(verified.signed.encoded_size, 0);
    }

    #[test]
    fn malformed_sizes_are_rejected_before_allocation() {
        let key = signing_key();
        let artifact = build_full_artifact(&vec![0x99; 4096], &spec(), &key).unwrap();
        let mut malformed = artifact.clone();
        malformed[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            parse_artifact(&malformed),
            Err(ArtifactError::InvalidManifestLength)
        ));
        let mut oversize = vec![0; KOTA3_MAX_PACKAGE_SIZE + 1];
        oversize[..8].copy_from_slice(KOTA3_MAGIC);
        assert!(matches!(
            parse_artifact(&oversize),
            Err(ArtifactError::SizeOverflow)
        ));
    }
}
