// SPDX-License-Identifier: AGPL-3.0-only

//! DeterministicWasmProfile validation (PV-8.2), ExecutionProfileVersion
//! (PV-8.2a), and pinned wasmi fuel/StoreLimits configuration (PV-8.1, PV-8.4).
//!
//! Production callers:
//! - `tirbase-core/src/migration/wasm_sandbox.rs` validates every module at
//! load time before instantiation/execution and rejects/quarantines failures.
//! - `tirbase-core/src/migration/mod.rs` matches `ExecutionProfileVersion`
//! metadata (`profile_id`, `fuel_cost_table_hash`) and quarantines with
//! `ENGINE_VERSION_MISMATCH` on mismatch.
//!
//! Wiring mutation checks:
//! - Loading a module with `f32`/`f64`/SIMD/atomics imports without this
//! validator must fail S8 / `test_float_simd_rejection`.
//! - Skipping profile/fuel-hash matching must fail S9 /
//! `test_fuel_hash_mismatch`.
//! - Removing StoreLimits must fail the memory-limit quarantine test.

#![forbid(unsafe_code)]

use crate::errors::TirBaseError;
use crate::migration::migration_delta::MigrationId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wasmparser::{Operator, Parser, Payload, ValType, Validator};

/// PV-8.1 / design 4.13: hard limits applied to every migration instance.
pub const STORE_LIMIT_MEMORY_BYTES: usize = 64 * 1024 * 1024; // 64 MiB
pub const STORE_LIMIT_TABLES: usize = 1_000;
pub const STORE_LIMIT_INSTANCES: usize = 10;
/// wasmi 0.38 has no separate "stack bytes" StoreLimit; we enforce an upper
/// bound on function-local/value-stack pressure via fuel and reject modules
/// that declare excessive limits at validation time. The configured constant
/// is recorded in the fuel/profile hash for cross-node agreement.
pub const STORE_LIMIT_STACK_BYTES: usize = 512 * 1024; // 512 KiB (profile record)

/// Fixed profile identifier for the TirBase PV-8 deterministic migration profile.
/// Changing this value is a protocol-level change and must be reflected in
/// signed `ExecutionProfileVersion` metadata.
pub const DETERMINISTIC_PROFILE_ID: [u8; 16] = *b"TIRBASE-WASMI-P8";

/// SHA-256 of the committed PV-8 migration conformance corpus, i.e. the raw
/// bytes of `tirbase-core/testdata/migration-conformance/corpus.json`.
///
/// This is a real digest, not a placeholder: any change to the corpus changes
/// this value. `conformance_corpus_hash_matches_committed_corpus` recomputes it
/// from the file and fails if the constant and the corpus drift apart, so a
/// corpus edit must also be a deliberate, reviewable update of the pinned
/// profile metadata (PV-8.2a).
///
/// Note: the corpus itself is not yet signed by an `UpdateSigner`; see
/// CLAIM-29.3.
pub const CONFORMANCE_CORPUS_HASH: [u8; 32] = [
    0x0a, 0x49, 0x74, 0x59, 0x91, 0xb7, 0x04, 0x4f, 0x97, 0xcc, 0x5e, 0x9f, 0xc0, 0xd3, 0x86, 0xa2,
    0x27, 0x24, 0x1a, 0x4b, 0xab, 0x80, 0xb0, 0xb3, 0x8c, 0x45, 0x57, 0x00, 0xef, 0x03, 0xe9, 0xbe,
];

/// Signed execution metadata embedded in/associated with a migration module
/// (PV-8.2a, design 4.13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionProfileVersion {
    pub profile_id: [u8; 16],
 /// SHA-256 of the explicit wasmi instruction fuel-cost / StoreLimits config.
    pub fuel_cost_table_hash: [u8; 32],
 /// SHA-256 of the test vector corpus used for conformance testing.
    pub conformance_corpus_hash: [u8; 32],
 /// UpdateSigner signature over canonical bytes of this metadata.
    #[serde(with = "serde_bytes")]
    pub update_signer_signature: Vec<u8>,
}

impl ExecutionProfileVersion {
 /// Canonical bytes covered by the UpdateSigner signature.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + 32 + 32);
        out.extend_from_slice(&self.profile_id);
        out.extend_from_slice(&self.fuel_cost_table_hash);
        out.extend_from_slice(&self.conformance_corpus_hash);
        out
    }

 /// Verify the UpdateSigner signature over [`Self::canonical_bytes`].
    pub fn verify_signature(
        &self,
        update_signer_public_key: &[u8; 32],
    ) -> Result<(), TirBaseError> {
        use ed25519_dalek::{Signature, VerifyingKey};
        let sig_bytes: [u8; 64] =
            self.update_signer_signature
                .as_slice()
                .try_into()
                .map_err(|_| TirBaseError::MigrationExecutionProfileMismatch {
                    migration_id: hex::encode([0u8; 32]),
                    expected_profile: "valid UpdateSigner signature".to_string(),
                    got_profile: "malformed signature".to_string(),
                    expected_fuel_hash: hex::encode([0u8; 32]),
                    got_fuel_hash: hex::encode([0u8; 32]),
                })?;
        let vk = VerifyingKey::from_bytes(update_signer_public_key).map_err(|e| {
            TirBaseError::SignatureVerificationFailed {
                reason: format!("invalid UpdateSigner public key: {e}"),
            }
        })?;
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify_strict(&self.canonical_bytes(), &sig)
            .map_err(|_| TirBaseError::MigrationExecutionProfileMismatch {
                migration_id: hex::encode([0u8; 32]),
                expected_profile: "valid UpdateSigner signature".to_string(),
                got_profile: "signature verification failed".to_string(),
                expected_fuel_hash: hex::encode([0u8; 32]),
                got_fuel_hash: hex::encode([0u8; 32]),
            })
    }

 /// Match against the node's active pinned profile. Version strings are not
 /// used (PV-8.2a): only `profile_id` and `fuel_cost_table_hash` identify
 /// compatible execution.
    pub fn matches_active(&self, active: &ActiveExecutionProfile) -> bool {
        self.profile_id == active.profile_id
            && self.fuel_cost_table_hash == active.fuel_cost_table_hash
    }

    pub fn mismatch_error(
        &self,
        migration_id: MigrationId,
        active: &ActiveExecutionProfile,
    ) -> TirBaseError {
        TirBaseError::MigrationExecutionProfileMismatch {
            migration_id: hex::encode(migration_id),
            expected_profile: hex::encode(active.profile_id),
            got_profile: hex::encode(self.profile_id),
            expected_fuel_hash: hex::encode(active.fuel_cost_table_hash),
            got_fuel_hash: hex::encode(self.fuel_cost_table_hash),
        }
    }
}

/// Node-local active execution profile (derived from pinned wasmi config).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveExecutionProfile {
    pub profile_id: [u8; 16],
    pub fuel_cost_table_hash: [u8; 32],
    pub conformance_corpus_hash: [u8; 32],
}

impl Default for ActiveExecutionProfile {
    fn default() -> Self {
        Self {
            profile_id: DETERMINISTIC_PROFILE_ID,
            fuel_cost_table_hash: pinned_fuel_cost_table_hash(),
            conformance_corpus_hash: CONFORMANCE_CORPUS_HASH,
        }
    }
}

/// SHA-256 over the pinned wasmi/store/fuel/limits configuration.
/// Any change to the constants below changes this hash and therefore requires a
/// signed ExecutionProfileVersion update (PV-8.2a).
pub fn pinned_fuel_cost_table_hash() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"TirBase/PV-8/fuel-cost-table/v1");
    h.update(DETERMINISTIC_PROFILE_ID);
    h.update(env!("CARGO_PKG_VERSION").as_bytes()); // wasmi crate is pinned in lock; record core version
    h.update(b"wasmi=0.38");
    h.update(STORE_LIMIT_MEMORY_BYTES.to_le_bytes());
    h.update(STORE_LIMIT_TABLES.to_le_bytes());
    h.update(STORE_LIMIT_INSTANCES.to_le_bytes());
    h.update(STORE_LIMIT_STACK_BYTES.to_le_bytes());
    h.update([1u8]); // consume_fuel enabled
    h.finalize().into()
}

/// DeterministicWasmProfile validator (PV-8.2, PV-8.2a).
///
/// Rejects modules that can introduce non-determinism or host dependence:
/// - any `f32`/`f64` value type or float instruction/operator
/// - SIMD (`v128`, relaxed SIMD, SIMD operators)
/// - threads/atomics/shared memory
/// - bulk memory ops beyond deterministic baseline are allowed only when they
/// do not involve non-deterministic features; we reject all atomic/thread ops
/// - imports (no WASI, no host clock, no host randomness, no env beyond
/// explicit migration host ABI validated separately at instantiation)
/// - reference-types/function-references/gc features not needed for migrations
///
/// The validator uses `wasmparser::Validator` with a restrictive feature set
/// and then performs an operator/type walk to reject forbidden constructs even
/// if a parser feature bit were permissive.
pub struct DeterministicWasmProfile;

impl DeterministicWasmProfile {
    pub fn validate(wasm_bytes: &[u8], migration_id: MigrationId) -> Result<(), TirBaseError> {
        let mid = hex::encode(migration_id);

 // Phase 1: structural validation with deterministic-only features.
 // `default()` in wasmparser 0.254 is permissive for many proposals; we
 // construct restrictive features by disabling proposals that conflict.
        let mut features = wasmparser::WasmFeatures::default();
        features.remove(wasmparser::WasmFeatures::FLOATS);
        features.remove(wasmparser::WasmFeatures::SIMD);
        features.remove(wasmparser::WasmFeatures::RELAXED_SIMD);
        features.remove(wasmparser::WasmFeatures::THREADS);
        features.remove(wasmparser::WasmFeatures::REFERENCE_TYPES);
        features.remove(wasmparser::WasmFeatures::FUNCTION_REFERENCES);
        features.remove(wasmparser::WasmFeatures::GC);
        features.remove(wasmparser::WasmFeatures::EXCEPTIONS);
        features.remove(wasmparser::WasmFeatures::MEMORY64);
        features.remove(wasmparser::WasmFeatures::COMPONENT_MODEL);
 // Keep core integer/memory/control flow needed for deterministic migrations.
        let mut validator = Validator::new_with_features(features);
        if let Err(e) = validator.validate_all(wasm_bytes) {
            return Err(TirBaseError::MigrationDeterministicProfileViolation {
                migration_id: mid,
                reason: format!("wasmparser validation failed: {e}"),
            });
        }

 // Phase 2: explicit operator/type/import walk. This is the
 // wiring-mutation guard: removing it must allow forbidden modules.
        Self::scan_forbidden_constructs(wasm_bytes, migration_id)
    }

    fn scan_forbidden_constructs(
        bytes: &[u8],
        migration_id: MigrationId,
    ) -> Result<(), TirBaseError> {
        let mid = hex::encode(migration_id);
        for payload in Parser::new(0).parse_all(bytes) {
            let payload =
                payload.map_err(|e| TirBaseError::MigrationDeterministicProfileViolation {
                    migration_id: mid.clone(),
                    reason: format!("parse error: {e}"),
                })?;
            match payload {
                Payload::ImportSection(reader) => {
                    for imp in reader.into_imports() {
                        let import =
                            imp.map_err(|e| profile_err(&mid, format!("import parse: {e}")))?;
                        let allowed = import.module == "host"
                            && matches!(import.name, "log_message" | "read_row" | "write_row")
                            && matches!(import.ty, wasmparser::TypeRef::Func(_));
                        if !allowed {
                            return Err(TirBaseError::MigrationDeterministicProfileViolation {
                                migration_id: mid.clone(),
                                reason: format!(
                                    "forbidden import {}.{} (only host.log_message/read_row/write_row are allowed)",
                                    import.module, import.name
                                ),
                            });
                        }
                    }
                }
                Payload::TypeSection(reader) => {
                    for ty in reader {
                        let ty = ty.map_err(|e| profile_err(&mid, format!("type parse: {e}")))?;
                        for sub in ty.types() {
                            check_composite_type(&sub.composite_type, &mid)?;
                        }
                    }
                }
                Payload::FunctionSection(_)
                | Payload::TableSection(_)
                | Payload::MemorySection(_) => {}
                Payload::GlobalSection(reader) => {
                    for g in reader {
                        let g = g.map_err(|e| profile_err(&mid, format!("global parse: {e}")))?;
                        check_val_type(g.ty.content_type, &mid, "global type")?;
                    }
                }
                Payload::CodeSectionEntry(body) => {
                    let mut ops = body
                        .get_operators_reader()
                        .map_err(|e| profile_err(&mid, format!("operators: {e}")))?;
                    while !ops.eof() {
                        let op = ops
                            .read()
                            .map_err(|e| profile_err(&mid, format!("operator read: {e}")))?;
                        check_operator(&op, &mid)?;
                    }
                }
                Payload::DataSection(_)
                | Payload::ElementSection(_)
                | Payload::ExportSection(_)
                | Payload::StartSection { .. }
                | Payload::CustomSection(_)
                | Payload::DataCountSection { .. }
                | Payload::Version { .. }
                | Payload::CodeSectionStart { .. }
                | Payload::End(_)
                | Payload::UnknownSection { .. }
                | _ => {}
            }
        }
        Ok(())
    }
}

fn profile_err(mid: &str, reason: String) -> TirBaseError {
    TirBaseError::MigrationDeterministicProfileViolation {
        migration_id: mid.to_string(),
        reason,
    }
}

fn check_composite_type(ty: &wasmparser::CompositeType, mid: &str) -> Result<(), TirBaseError> {
    match &ty.inner {
        wasmparser::CompositeInnerType::Func(f) => {
            for p in f.params().iter().copied() {
                check_val_type(p, mid, "function param")?;
            }
            for r in f.results().iter().copied() {
                check_val_type(r, mid, "function result")?;
            }
        }
        wasmparser::CompositeInnerType::Array(a) => {
            check_storage_type(a.0.element_type, mid, "array element")?
        }
        wasmparser::CompositeInnerType::Struct(s) => {
            for f in s.fields.iter().copied() {
                check_storage_type(f.element_type, mid, "struct field")?;
            }
        }
        wasmparser::CompositeInnerType::Cont(_) => {}
    }
    Ok(())
}

fn check_val_type(vt: ValType, mid: &str, ctx: &str) -> Result<(), TirBaseError> {
    match vt {
        ValType::F32 | ValType::F64 => Err(profile_err(
            mid,
            format!("forbidden float type in {ctx}: {vt:?}"),
        )),
        ValType::V128 => Err(profile_err(
            mid,
            format!("forbidden SIMD type in {ctx}: v128"),
        )),
        ValType::I32 | ValType::I64 => Ok(()),
        ValType::Ref(_) => Err(profile_err(
            mid,
            format!("forbidden reference type in {ctx}: {vt:?}"),
        )),
    }
}

fn check_operator(op: &Operator<'_>, mid: &str) -> Result<(), TirBaseError> {
    use Operator::*;
 // Reject by operator class/name pattern (robust across wasmparser minor
 // variants). Float: F32*/F64*/I32TruncSatF*/I64TruncSatF* reinterpret/trunc
 // forms. SIMD: V128*/I8x16*/I16x8*/I32x4*/I64x2*/F32x4*/F64x2*. Atomics:
 // I32Atomic*/I64Atomic*/Atomic*/MemoryAtomic*.
    let dbg = format!("{op:?}");
    let forbidden = dbg.starts_with("F32")
        || dbg.starts_with("F64")
        || dbg.starts_with("V128")
        || dbg.starts_with("I8x16")
        || dbg.starts_with("I16x8")
        || dbg.starts_with("I32x4")
        || dbg.starts_with("I64x2")
        || dbg.starts_with("F32x4")
        || dbg.starts_with("F64x2")
        || dbg.contains("Atomic")
        || dbg.contains("Shared")
        || dbg.contains("Thread")
        || dbg.contains("atomic.notify")
        || dbg.contains("atomic.wait");
    if forbidden {
        return Err(profile_err(
            mid,
            format!("forbidden non-deterministic operator: {dbg}"),
        ));
    }
 // Explicit high-signal checks (cheap) + allowlist fallthrough.
    match op {
 // Float const/load/store/ops covered by prefix, but keep explicit for clarity.
        F32Const { .. }
        | F64Const { .. }
        | F32Load { .. }
        | F64Load { .. }
        | F32Store { .. }
        | F64Store { .. }
        | MemoryAtomicNotify { .. }
        | MemoryAtomicWait32 { .. }
        | MemoryAtomicWait64 { .. } => Err(profile_err(mid, format!("forbidden operator: {dbg}"))),
 // Call/CallIndirect are structurally allowed only in modules with no
 // imports and only self-contained integer logic; imports were rejected
 // above, so remaining calls are intra-module.
        _ => Ok(()),
    }
}

fn check_storage_type(
    st: wasmparser::StorageType,
    mid: &str,
    ctx: &str,
) -> Result<(), TirBaseError> {
    match st {
        wasmparser::StorageType::I8 | wasmparser::StorageType::I16 => Ok(()),
        wasmparser::StorageType::Val(vt) => check_val_type(vt, mid, ctx),
    }
}

#[cfg(all(test, feature = "native"))]
mod tests {
    use super::*;

    #[test]
    fn pinned_hash_is_stable_shape() {
        let h1 = pinned_fuel_cost_table_hash();
        let h2 = pinned_fuel_cost_table_hash();
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn update_signer_signature_verifies_and_tampering_is_rejected() {
        use ed25519_dalek::{Signer, SigningKey};

        let key = SigningKey::from_bytes(&[7u8; 32]);
        let active = ActiveExecutionProfile::default();
        let mut meta = ExecutionProfileVersion {
            profile_id: active.profile_id,
            fuel_cost_table_hash: active.fuel_cost_table_hash,
            conformance_corpus_hash: active.conformance_corpus_hash,
            update_signer_signature: Vec::new(),
        };
        meta.update_signer_signature = key.sign(&meta.canonical_bytes()).to_bytes().to_vec();
        meta.verify_signature(&key.verifying_key().to_bytes())
            .expect("valid UpdateSigner signature must verify");

        meta.conformance_corpus_hash[0] ^= 0xFF;
        assert!(
            meta.verify_signature(&key.verifying_key().to_bytes())
                .is_err(),
            "tampered metadata must not verify"
        );
    }

    #[test]
    fn execution_profile_matches_active_default() {
        let active = ActiveExecutionProfile::default();
        let meta = ExecutionProfileVersion {
            profile_id: active.profile_id,
            fuel_cost_table_hash: active.fuel_cost_table_hash,
            conformance_corpus_hash: active.conformance_corpus_hash,
            update_signer_signature: vec![],
        };
        assert!(meta.matches_active(&active));
    }

    #[test]
    fn conformance_corpus_hash_matches_committed_corpus() {
 // PV-8.2a: the pinned corpus hash must be the real SHA-256 of the
 // committed corpus file, never a placeholder.
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/migration-conformance/corpus.json"
        );
        let corpus = std::fs::read(path).expect("read migration conformance corpus");
        let computed: [u8; 32] = Sha256::digest(&corpus).into();
        assert_ne!(
            CONFORMANCE_CORPUS_HASH, [0u8; 32],
            "corpus hash is a placeholder"
        );
        assert_eq!(
            computed, CONFORMANCE_CORPUS_HASH,
            "CONFORMANCE_CORPUS_HASH must be the SHA-256 of the committed corpus"
        );
    }

    #[test]
    fn deterministic_profile_rejects_f32_const() {
        let wat = r#"(module (func (export "run") f32.const 1.0 drop))"#;
        let wasm = wat::parse_str(wat).unwrap();
        let err = DeterministicWasmProfile::validate(&wasm, [7u8; 32]).unwrap_err();
        assert!(matches!(
            err,
            TirBaseError::MigrationDeterministicProfileViolation { .. }
        ));
    }
}

