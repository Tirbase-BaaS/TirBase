// SPDX-License-Identifier: AGPL-3.0-only

//! Fixture generator for the TypeScript SDK's real-WASM end-to-end tests.
//!
//! The SDK test suite runs in Node against the compiled WASM module, which has
//! no Ed25519/Biscuit minting primitives of its own. This tool produces the
//! cryptographic fixtures with the *production* helpers — `auth::biscuit`
//! (mint + caveat) and `identity::file_key_provider` (DID derivation and
//! signing) — and prints them as one JSON object on stdout. The WASM module
//! still verifies every token and signature: the fixtures are inputs, never
//! the asserted path.
//!
//! Usage:
//!   cargo run -q -p tirbase-core --example wasm_e2e_fixtures
//!
//! Output fields:
//! * `rootCaSeedHex` / `rootCaPublicHex` — the deployment root CA.
//! * `managerTokenHex` — a valid `RevocationManager` token from the root CA.
//! * `foreignTokenHex` — a valid token minted by a *different* CA (rejection
//!   fixture: the deployment does not trust that key).
//! * `auditorTokenHex` — a trusted-CA token with the wrong role (`Auditor`).
//! * `disasterAlertTokenHex` — a token carrying `caveat("disaster-alert")`.
//! * `coManagers` — two independent Manager identities and their Ed25519
//!   signatures over `terminationMessage`.

use tirbase_core::auth::biscuit;
use tirbase_core::identity::file_key_provider::InMemoryKeyProvider;
use tirbase_core::traits::KeyProvider;

/// Canonical message the co-signing Managers sign for the Saturate_Mode
/// termination test. The SDK forwards these bytes hex-encoded.
const TERMINATION_MESSAGE: &[u8] = b"tirbase-sdk-e2e:saturate-terminate:v1";

fn main() {
    let ca = InMemoryKeyProvider::generate().expect("root CA keypair");
    let foreign_ca = InMemoryKeyProvider::generate().expect("foreign CA keypair");
    let manager = InMemoryKeyProvider::generate().expect("manager identity");

    let manager_token = biscuit::create_token(
        manager.did(),
        "RevocationManager",
        3600,
        &ca.secret_seed(),
        false,
    )
    .expect("mint manager token");

    let foreign_token = biscuit::create_token(
        "did:key:z6MkForeignManager",
        "RevocationManager",
        3600,
        &foreign_ca.secret_seed(),
        false,
    )
    .expect("mint foreign token");

    // Signed by the trusted CA but carrying the wrong role: revocation
    // initiation must reject it even though the signature is valid.
    let auditor_token = biscuit::create_token(
        "did:key:z6MkAuditor",
        "Auditor",
        3600,
        &ca.secret_seed(),
        false,
    )
    .expect("mint auditor token");

    let disaster_alert_token = biscuit::create_token_with_caveat(
        manager.did(),
        "PolicyAuthority",
        3600,
        "disaster-alert",
        &ca.secret_seed(),
    )
    .expect("mint disaster-alert token");

    let co_managers: Vec<serde_json::Value> = (0..2)
        .map(|_| {
            let signer = InMemoryKeyProvider::generate().expect("co-manager identity");
            let signature = signer.sign(TERMINATION_MESSAGE).expect("sign termination");
            serde_json::json!({
                "did": signer.did(),
                "signatureHex": hex::encode(signature.as_bytes()),
            })
        })
        .collect();

    let fixtures = serde_json::json!({
        "rootCaSeedHex": hex::encode(ca.secret_seed()),
        "rootCaPublicHex": hex::encode(ca.public_key_bytes()),
        "managerDid": manager.did(),
        "managerTokenHex": hex::encode(&manager_token),
        "foreignTokenHex": hex::encode(&foreign_token),
        "auditorTokenHex": hex::encode(&auditor_token),
        "disasterAlertTokenHex": hex::encode(&disaster_alert_token),
        "terminationMessage": String::from_utf8_lossy(TERMINATION_MESSAGE),
        "terminationMessageHex": hex::encode(TERMINATION_MESSAGE),
        "coManagers": co_managers,
    });

    println!(
        "{}",
        serde_json::to_string(&fixtures).expect("serialise fixtures")
    );
}
