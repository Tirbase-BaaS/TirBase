// SPDX-License-Identifier: AGPL-3.0-only

//! Signed postcondition evaluation for migration shadow output (PV-8.4).
//!
//! Postconditions are evaluated against the shadow run's store state (real
//! projection data). A failure discards the shadow and preserves pre-execution
//! state.

#![allow(dead_code)]

use crate::errors::TirBaseError;
use crate::events::{emit_migration, ReasonCode, Severity};
use crate::migration::migration_delta::{PostconditionCheck, SignedPostconditions};
use crate::schema::hash::SchemaIdentifierHash;
use crate::schema::Schema;
use crate::store::LocalStore;
use sha2::{Digest, Sha256};

/// Result of evaluating a signed postcondition set against shadow output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PostconditionOutcome {
    Passed,
    Failed { reason: String },
}

/// Evaluate `signed` postconditions against `shadow_store`.
///
/// Signature verification: if `signed.signer_public_key` and a non-empty
/// `signed.signature` are present, the Ed25519 signature over
/// `SHA-256(canonical_postcondition_bytes)` is verified. Unsigned/legacy
/// postcondition sets (empty signature) are accepted only when explicitly
/// allowed by the caller via `allow_unsigned` (test/legacy compatibility);
/// production migration deltas must carry a signature.
pub fn evaluate_postconditions(
    signed: &SignedPostconditions,
    shadow_store: &LocalStore,
    target_schema_hash: &SchemaIdentifierHash,
    target_schema: Option<&Schema>,
    migration_id_hex: &str,
    allow_unsigned: bool,
) -> Result<PostconditionOutcome, TirBaseError> {
    if !signed.signature.is_empty() || signed.signer_public_key.is_some() {
        verify_postcondition_signature(signed, migration_id_hex)?;
    } else if !allow_unsigned {
        return Ok(PostconditionOutcome::Failed {
            reason: "unsigned postconditions rejected (PV-8.4 requires signed postconditions)"
                .to_string(),
        });
    }

    for check in &signed.checks {
        if let Some(reason) =
            evaluate_check(check, shadow_store, target_schema_hash, target_schema)?
        {
            emit_migration(
                Severity::High,
                ReasonCode::PostconditionFailed,
                Some(migration_id_hex.to_string()),
                format!("[migration postcondition] failed: {reason}"),
            );
            return Ok(PostconditionOutcome::Failed { reason });
        }
    }

    Ok(PostconditionOutcome::Passed)
}

fn verify_postcondition_signature(
    signed: &SignedPostconditions,
    migration_id_hex: &str,
) -> Result<(), TirBaseError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let pk = signed
        .signer_public_key
        .ok_or_else(|| TirBaseError::AuthorisationFailed {
            reason: format!(
                "postcondition signer public key missing for migration {migration_id_hex}"
            ),
        })?;
    let sig_bytes: [u8; 64] =
        signed
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| TirBaseError::AuthorisationFailed {
                reason: format!(
                    "postcondition signature wrong length for migration {migration_id_hex}"
                ),
            })?;
    let verifying_key =
        VerifyingKey::from_bytes(&pk).map_err(|e| TirBaseError::AuthorisationFailed {
            reason: format!("invalid postcondition signer key: {e}"),
        })?;
    let msg = signed.canonical_signing_bytes();
    let sig = Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify_strict(&msg, &sig)
        .map_err(|e| TirBaseError::AuthorisationFailed {
            reason: format!(
                "postcondition signature verification failed for migration {migration_id_hex}: {e}"
            ),
        })
}

fn evaluate_check(
    check: &PostconditionCheck,
    shadow_store: &LocalStore,
    target_schema_hash: &SchemaIdentifierHash,
    target_schema: Option<&Schema>,
) -> Result<Option<String>, TirBaseError> {
    match check {
        PostconditionCheck::RowCount { table, expected } => {
            let rows = shadow_store.count_rows(table)?;
            if rows != *expected {
                return Ok(Some(format!(
                    "row count mismatch for table {table}: expected {expected}, got {rows}"
                )));
            }
        }
        PostconditionCheck::FieldChecksum {
            table,
            field,
            expected_sha256_hex,
        } => {
            let actual = field_checksum_hex(shadow_store, table, field)?;
            if &actual != expected_sha256_hex {
                return Ok(Some(format!(
                    "field checksum mismatch for {table}.{field}: expected {expected_sha256_hex}, got {actual}"
                )));
            }
        }
        PostconditionCheck::SchemaValid { expected_hash } => {
            let want = expected_hash.as_ref().unwrap_or(target_schema_hash);
            if let Some(schema) = target_schema {
                let got = schema.identifier_hash();
                if &got != want {
                    return Ok(Some(format!(
                        "schema hash mismatch: expected {}, got {}",
                        hex::encode(want),
                        hex::encode(got)
                    )));
                }
 // Basic structural validity: printable + parseable.
                let printed = crate::schema::printer::print(schema);
                crate::schema::parser::parse(&printed).map_err(|errors| {
                    TirBaseError::DeltaMalformed {
                        reason: format!(
                            "target schema failed parser validation: {} error(s)",
                            errors.len()
                        ),
                    }
                })?;
            } else {
 // No schema definition registered; accept hash match by contract.
                if want != target_schema_hash {
                    return Ok(Some(format!(
                        "schema hash mismatch (no definition): expected {}, got {}",
                        hex::encode(want),
                        hex::encode(target_schema_hash)
                    )));
                }
            }
        }
    }
    Ok(None)
}

/// SHA-256 over canonical `(key, field_value_json)` rows in key order for real data.
pub fn field_checksum_hex(
    store: &LocalStore,
    table: &str,
    field: &str,
) -> Result<String, TirBaseError> {
    let mut rows = store.read_all_rows(table)?;
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let mut hasher = Sha256::new();
    for (key, value) in rows {
        let field_val = value.get(field).cloned().unwrap_or(serde_json::Value::Null);
        let canonical =
            serde_json::to_vec(&(key, field_val)).map_err(|e| TirBaseError::DeltaMalformed {
                reason: format!("field checksum canonicalisation failed: {e}"),
            })?;
        hasher.update((canonical.len() as u32).to_le_bytes());
        hasher.update(canonical);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn row_count_check_passes_and_fails() {
        let mut store = LocalStore::open(":memory:").expect("store");
        store.write("t", "k1", &json!({"a":1})).expect("write");
        let check = PostconditionCheck::RowCount {
            table: "t".to_string(),
            expected: 1,
        };
        assert!(evaluate_check(&check, &store, &[0u8; 32], None)
            .unwrap()
            .is_none());
        let bad = PostconditionCheck::RowCount {
            table: "t".to_string(),
            expected: 2,
        };
        assert!(evaluate_check(&bad, &store, &[0u8; 32], None)
            .unwrap()
            .is_some());
    }
}
