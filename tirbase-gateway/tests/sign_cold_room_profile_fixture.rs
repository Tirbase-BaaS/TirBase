//! One-off helper to generate signed fixture for profiles/cold_room.toml (CLAIM-34.5).
//! Run with: cargo test -p tirbase-gateway --test sign_cold_room_profile_fixture -- --ignored --nocapture

use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;
use tirbase_gateway::profiles::{load_profile_from_path, sign_parsed_profile};

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
#[ignore]
fn generate_signed_cold_room_fixture() {
    let seed = [0x34u8; 32];
    let pa = InMemoryKeyProvider::from_seed(seed);
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("profiles")
        .join("cold_room.toml");
    let profile = load_profile_from_path(&path).expect("parse");
    let signed = sign_parsed_profile(profile, &pa);
    let sig = match signed.signature {
        tirbase_types::DeviceSignature::Ed25519(b) => b,
        _ => panic!("expected ed25519"),
    };
    let hex = hex_encode(&sig);
    eprintln!("FIXTURE_PA_DID={}", pa.did());
    eprintln!("FIXTURE_PA_PK_HEX={}", hex_encode(&pa.public_key_bytes()));
    eprintln!("FIXTURE_SIGNATURE_HEX={hex}");
    println!("{hex}");
}
