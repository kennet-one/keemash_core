// SPDX-License-Identifier: GPL-2.0-only

use keemash_keelink::ota::{
    build_full_artifact, parse_artifact, verify_artifact, ArtifactBuildSpec,
};
use p256::ecdsa::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use std::collections::HashMap;
use std::fs;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

fn fail(message: impl std::fmt::Display) -> ! {
    eprintln!("kota3: {message}");
    std::process::exit(2);
}

fn parse_options(args: impl Iterator<Item = String>) -> HashMap<String, String> {
    let values: Vec<String> = args.collect();
    if !values.len().is_multiple_of(2) {
        fail("options must be provided as --name value pairs");
    }
    let mut options = HashMap::new();
    for pair in values.chunks_exact(2) {
        if !pair[0].starts_with("--") || pair[0].len() <= 2 {
            fail(format!("invalid option {}", pair[0]));
        }
        options.insert(pair[0][2..].to_owned(), pair[1].clone());
    }
    options
}

fn required(options: &HashMap<String, String>, name: &str) -> String {
    options
        .get(name)
        .cloned()
        .unwrap_or_else(|| fail(format!("missing --{name}")))
}

fn read_hex(path: &Path) -> Vec<u8> {
    let value = fs::read_to_string(path)
        .unwrap_or_else(|error| fail(format!("cannot read {}: {error}", path.display())));
    hex::decode(value.trim())
        .unwrap_or_else(|error| fail(format!("invalid hex in {}: {error}", path.display())))
}

fn write_private(path: &Path, key: &SigningKey) {
    let parent = path
        .parent()
        .unwrap_or_else(|| fail("private key needs an absolute path"));
    let parent = parent
        .canonicalize()
        .unwrap_or_else(|error| fail(format!("cannot resolve private key directory: {error}")));
    if parent
        .ancestors()
        .any(|directory| directory.join(".git").exists())
    {
        fail("private signing key must be outside every Git repository");
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap_or_else(|error| fail(format!("cannot create {}: {error}", path.display())));
    file.write_all(format!("{}\n", hex::encode(key.to_bytes())).as_bytes())
        .unwrap_or_else(|error| fail(format!("cannot write {}: {error}", path.display())));
}

fn write_public(path: &Path, key: &VerifyingKey) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap_or_else(|error| fail(format!("cannot create {}: {error}", path.display())));
    file.write_all(format!("{}\n", hex::encode(key.to_encoded_point(false).as_bytes())).as_bytes())
        .unwrap_or_else(|error| fail(format!("cannot write {}: {error}", path.display())));
}

fn keygen(options: HashMap<String, String>) {
    let private_path = PathBuf::from(required(&options, "private"));
    let public_path = PathBuf::from(required(&options, "public"));
    if !private_path.is_absolute() || !public_path.is_absolute() {
        fail("key paths must be absolute and the private path must be outside Git");
    }
    if private_path == public_path {
        fail("private and public key paths must differ");
    }
    if private_path.exists() || public_path.exists() {
        fail("refusing to overwrite an existing signing key");
    }
    let key = SigningKey::random(&mut OsRng);
    write_private(&private_path, &key);
    write_public(&public_path, key.verifying_key());
    println!("generated P-256 firmware key {}", public_path.display());
}

fn pack(options: HashMap<String, String>) {
    let image_path = PathBuf::from(required(&options, "image"));
    let output_path = PathBuf::from(required(&options, "output"));
    let key_path = PathBuf::from(required(&options, "private-key"));
    let key_location = key_path
        .canonicalize()
        .unwrap_or_else(|error| fail(format!("cannot resolve signing key path: {error}")));
    if key_location
        .ancestors()
        .any(|directory| directory.join(".git").exists())
    {
        fail("private signing key must be outside every Git repository");
    }
    let image = fs::read(&image_path)
        .unwrap_or_else(|error| fail(format!("cannot read {}: {error}", image_path.display())));
    let key_bytes = read_hex(&key_path);
    let key = SigningKey::from_slice(&key_bytes)
        .unwrap_or_else(|_| fail("private key must contain exactly 32 bytes"));
    let parse_u32 = |name: &str| {
        required(&options, name)
            .parse::<u32>()
            .unwrap_or_else(|_| fail(format!("--{name} must be an unsigned integer")))
    };
    let spec = ArtifactBuildSpec {
        project_name: &required(&options, "project"),
        chip_target: &required(&options, "chip"),
        firmware_version: &required(&options, "version"),
        build_commit: &required(&options, "commit"),
        minimum_core_version: parse_u32("minimum-core"),
        minimum_fabric_schema: parse_u32("minimum-schema"),
        required_app_slot_size: parse_u32("slot-size"),
        signing_key_id: &required(&options, "key-id"),
    };
    let artifact = build_full_artifact(&image, &spec, &key).unwrap_or_else(|error| fail(error));
    fs::write(&output_path, &artifact)
        .unwrap_or_else(|error| fail(format!("cannot write {}: {error}", output_path.display())));
    let verified = verify_artifact(&artifact, key.verifying_key(), None)
        .unwrap_or_else(|error| fail(format!("self-verification failed: {error}")));
    println!(
        "packed {} bytes into {} bytes artifact={} blocks={}",
        image.len(),
        artifact.len(),
        hex::encode(verified.artifact_id),
        verified.signed.block_count
    );
}

fn verify(options: HashMap<String, String>) {
    let artifact_path = PathBuf::from(required(&options, "artifact"));
    let public_path = PathBuf::from(required(&options, "public-key"));
    let artifact = fs::read(&artifact_path)
        .unwrap_or_else(|error| fail(format!("cannot read {}: {error}", artifact_path.display())));
    let public = read_hex(&public_path);
    let key = VerifyingKey::from_sec1_bytes(&public)
        .unwrap_or_else(|_| fail("public key must be a valid SEC1 P-256 point"));
    let verified = verify_artifact(&artifact, &key, None).unwrap_or_else(|error| fail(error));
    println!(
        "verified project={} version={} artifact={} raw={} encoded={} blocks={}",
        verified.signed.project_name,
        verified.signed.firmware_version,
        hex::encode(verified.artifact_id),
        verified.signed.raw_size,
        verified.signed.encoded_size,
        verified.signed.block_count
    );
}

fn inspect(options: HashMap<String, String>) {
    let artifact_path = PathBuf::from(required(&options, "artifact"));
    let artifact = fs::read(&artifact_path)
        .unwrap_or_else(|error| fail(format!("cannot read {}: {error}", artifact_path.display())));
    let (manifest, signed, payload) = parse_artifact(&artifact).unwrap_or_else(|error| fail(error));
    println!(
        "project={} chip={} version={} raw={} encoded={} payload={} blocks={} key={}",
        signed.project_name,
        signed.chip_target,
        signed.firmware_version,
        signed.raw_size,
        signed.encoded_size,
        payload.len(),
        manifest.blocks.len(),
        signed.signing_key_id
    );
}

fn main() {
    let mut args = std::env::args().skip(1);
    let command = args
        .next()
        .unwrap_or_else(|| fail("usage: kota3 <keygen|pack|verify|inspect> [--name value ...]"));
    let options = parse_options(args);
    match command.as_str() {
        "keygen" => keygen(options),
        "pack" => pack(options),
        "verify" => verify(options),
        "inspect" => inspect(options),
        _ => fail(format!("unknown command {command}")),
    }
}
