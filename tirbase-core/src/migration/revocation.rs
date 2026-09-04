//! Migration revocation — halt in-progress transforms, block future execution (Req 18.5–18.7).
//!
//! Req 18.7 known-hash gate: a `MigrationRevocationDelta` is only accepted
//! when its `target_migration_id` is a **known, previously-seen** migration
//! hash — one this device received as a CA-validated `MigrationDelta`
//! (recorded by `SchemaMigrationEngine::prepare_migration`).  An
//! arbitrary-hash revocation is rejected with
//! [`TirBaseError::UnknownMigrationHash`] instead of permanently poisoning
//! the registry with a block on a migration that was never distributed.

#![allow(dead_code, unused_variables, unused_imports)]

use crate::crdt::delta::Did;
use crate::errors::TirBaseError;
use crate::migration::migration_delta::{MigrationId, MigrationRevocationDelta};
use std::collections::HashSet;

// ─── DID resolution helper ───────────────────────────────────────────────────

/// Decode a `did:key:z6Mk…` DID to its 32-byte Ed25519 public key.
///
/// Delegates to the canonical [`crate::identity::did::resolve_did`].  (This
/// helper previously re-implemented resolution but forgot the multibase `z`
/// marker, so real manager DIDs — always `did:key:z6Mk…` — could never be
/// resolved and every migration-revocation signature failed verification.)
pub fn resolve_did_key_to_public_key(did: &str) -> Result<[u8; 32], TirBaseError> {
    crate::identity::did::resolve_did(&did.to_string())
}

// ─── RevocationRecord ────────────────────────────────────────────────────────

/// A log entry recording a successfully applied revocation.
#[derive(Debug, Clone)]
pub struct RevocationRecord {
    pub migration_id: MigrationId,
    /// Manager DIDs that authorised this revocation.
    pub authorised_by: Vec<Did>,
    /// UTC timestamp (microseconds) when revocation was applied.
    pub revoked_at: i64,
}

// ─── RevokedMigrationRegistry ────────────────────────────────────────────────

/// Registry of revoked migration IDs.
/// Once a migration is revoked it can never be applied again.
#[derive(Debug, Default)]
pub struct RevokedMigrationRegistry {
    /// Set of permanently blocked migration IDs.
    revoked: HashSet<MigrationId>,
    /// Migration hashes this device has genuinely **seen**: every
    /// CA-validated `MigrationDelta` received (its SHA-256 cleared the
    /// zero-trust gate) is recorded here by
    /// [`record_known_migration`](Self::record_known_migration).
    ///
    /// A `MigrationRevocationDelta` is only accepted when it targets a hash
    /// in this set (Req 18.7) — revoking a hash that was never distributed
    /// would permanently block nothing real while letting an attacker poison
    /// the audit log and block future, unrelated migrations under a
    /// compromised signer.
    known: HashSet<MigrationId>,
    /// Append-only audit log of all revocation events.
    revocation_log: Vec<RevocationRecord>,
    /// Migrations that are currently in-progress (sandbox running).
    /// On revocation these must be halted (Req 18.6).
    in_progress: HashSet<MigrationId>,
}

impl RevokedMigrationRegistry {
    /// Record `id` as a known, previously-seen migration hash (Req 18.7).
    ///
    /// Production caller: [`crate::migration::SchemaMigrationEngine::prepare_migration`]
    /// records every migration whose CA signature and embedded SHA-256 clear
    /// the zero-trust gate — the funnel every inbound `MigrationDelta` passes
    /// through (the native CoreHandle dispatch job and the synchronous
    /// `receive_migration_delta` path, which is the WASM inbound arm).  A hash
    /// is only ever recorded after its transform bytes verified, so junk can
    /// never mark itself as known.
    pub(crate) fn record_known_migration(&mut self, id: MigrationId) {
        self.known.insert(id);
    }

    /// Whether `id` is a known, previously-seen migration hash (Req 18.7).
    pub(crate) fn is_known_migration(&self, id: &MigrationId) -> bool {
        self.known.contains(id)
    }

    /// Check if a migration has been revoked.
    pub fn is_revoked(&self, id: &MigrationId) -> bool {
        self.revoked.contains(id)
    }

    /// Mark a migration as currently executing in the sandbox.
    ///
    /// Call this before starting `execute_migration()`; call `clear_in_progress()`
    /// when the sandbox exits (regardless of outcome).
    pub fn mark_in_progress(&mut self, id: MigrationId) {
        self.in_progress.insert(id);
    }

    /// Clear the in-progress flag (called when sandbox finishes or is halted).
    pub fn clear_in_progress(&mut self, id: &MigrationId) {
        self.in_progress.remove(id);
    }

    /// Check whether a migration is currently executing.
    pub fn is_in_progress(&self, id: &MigrationId) -> bool {
        self.in_progress.contains(id)
    }

    /// Check whether any migration is currently executing.
    pub fn has_in_progress(&self) -> bool {
        !self.in_progress.is_empty()
    }

    /// Process an incoming MigrationRevocationDelta (Req 18.5–18.7).
    ///
    /// Steps:
    /// 0. Reject if `target_migration_id` is not a known, previously-seen
    ///    migration hash (Req 18.7).  This is checked first — before any
    ///    signature work — because a revocation for a hash this device never
    ///    received cannot refer to a real migration and must not poison the
    ///    registry.
    /// 1. Verify each Manager DID signature over `target_migration_id`.
    /// 2. Check that at least `threshold_m` distinct, valid signatures are present.
    /// 3. If in-progress: mark as halted (caller must check `is_revoked` before executing).
    /// 4. Permanently block the migration ID.
    /// 5. Append a RevocationRecord to the audit log.
    ///
    /// Returns `Ok(true)` when a transform for `target_migration_id` was
    /// executing and has been halted — the caller is then responsible for
    /// actually interrupting the sandbox run (epoch interrupt via the
    /// execution registry on the wasmtime side) so it stops before its
    /// timeout instead of running to completion behind the revoker.
    pub fn apply_revocation(
        &mut self,
        revocation: MigrationRevocationDelta,
        threshold_m: usize,
    ) -> Result<bool, TirBaseError> {
        // ── 0: known-hash gate (Req 18.7) ───────────────────────────────────
        // A revocation may only target a migration hash this device has
        // genuinely seen (a CA-validated MigrationDelta for it was received).
        // Arbitrary hashes are rejected rather than accepted.
        if !self.known.contains(&revocation.target_migration_id) {
            let migration_id_hex = hex::encode(revocation.target_migration_id);
            eprintln!(
                "[revocation] Rejected: target migration hash {migration_id_hex} was \
                 never seen by this device (Req 18.7)"
            );
            return Err(TirBaseError::UnknownMigrationHash {
                migration_id: migration_id_hex,
            });
        }

        let mut halted = false;
        // ── 1 & 2: verify signatures and count valid distinct ones ──────────
        let signed_payload = &revocation.target_migration_id[..];
        let mut valid_managers: Vec<Did> = Vec::new();

        for ms in &revocation.signatures {
            // Resolve the manager's DID to its public key.
            let public_key = match resolve_did_key_to_public_key(&ms.manager_did) {
                Ok(pk) => pk,
                Err(e) => {
                    eprintln!(
                        "[revocation] DID resolution failed for {}: {e}",
                        ms.manager_did
                    );
                    continue; // skip invalid DIDs — don't count them
                }
            };

            // Verify the Ed25519 signature.
            let sig_bytes = match ms.signature.as_bytes() {
                Some(b) => b,
                None => {
                    eprintln!(
                        "[revocation] Malformed signature from {}: wrong length",
                        ms.manager_did
                    );
                    continue;
                }
            };

            use ed25519_dalek::{Signature, VerifyingKey};
            let verifying_key = match VerifyingKey::from_bytes(&public_key) {
                Ok(vk) => vk,
                Err(e) => {
                    eprintln!(
                        "[revocation] Invalid public key for {}: {e}",
                        ms.manager_did
                    );
                    continue;
                }
            };

            let sig = Signature::from_bytes(&sig_bytes);
            match verifying_key.verify_strict(signed_payload, &sig) {
                Ok(_) => {
                    // Only count distinct manager DIDs.
                    if !valid_managers.contains(&ms.manager_did) {
                        valid_managers.push(ms.manager_did.clone());
                    }
                }
                Err(e) => {
                    eprintln!(
                        "[revocation] Signature verification failed for {}: {e}",
                        ms.manager_did
                    );
                }
            }
        }

        // Check threshold (Req 18.7).
        if valid_managers.len() < threshold_m {
            return Err(TirBaseError::ThresholdNotMet {
                got: valid_managers.len(),
                need: threshold_m,
            });
        }

        // ── 3: halt in-progress execution ────────────────────────────────────
        // If a transform for the target is executing, flag the halt for the
        // caller (which must epoch-interrupt the running sandbox — Req 18.6).
        // The `in_progress` marker itself is deliberately NOT cleared here:
        // it is only removed when the sandbox run actually exits (the caller's
        // `finish_migration`), so schema-migration serialisation holds even if
        // the interrupt misses the run and it has to fall through to its epoch
        // timeout — a revoked-but-still-running transform can never overlap a
        // subsequent migration.
        if self.in_progress.contains(&revocation.target_migration_id) {
            eprintln!(
                "[revocation] Halting in-progress migration {:?}",
                revocation.target_migration_id
            );
            halted = true;
        }

        // ── 4: permanently block ─────────────────────────────────────────────
        self.revoked.insert(revocation.target_migration_id);

        // ── 5: audit log ──────────────────────────────────────────────────────
        use std::time::{SystemTime, UNIX_EPOCH};
        let revoked_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_micros() as i64)
            .unwrap_or(0);

        self.revocation_log.push(RevocationRecord {
            migration_id: revocation.target_migration_id,
            authorised_by: valid_managers,
            revoked_at,
        });

        eprintln!(
            "[revocation] Migration {:?} revoked and permanently blocked.",
            revocation.target_migration_id
        );

        Ok(halted)
    }

    /// Return the full revocation audit log.
    pub fn revocation_log(&self) -> &[RevocationRecord] {
        &self.revocation_log
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::delta::Ed25519Signature;
    use crate::crdt::derive_did_from_public_key;
    use crate::identity::keypair::{generate_keypair, sign};
    use crate::migration::migration_delta::{ManagerSignature, MigrationRevocationDelta};

    fn make_signed_revocation(
        target: MigrationId,
        signers: &[([u8; 32], String)], // (secret, did)
    ) -> MigrationRevocationDelta {
        let sigs: Vec<ManagerSignature> = signers
            .iter()
            .map(|(secret, did)| {
                let sig = sign(secret, &target).expect("sign");
                ManagerSignature {
                    manager_did: did.clone(),
                    signature: sig,
                }
            })
            .collect();

        MigrationRevocationDelta {
            target_migration_id: target,
            signatures: sigs,
            created_at: 0,
        }
    }

    fn make_identity() -> ([u8; 32], String) {
        let (secret, public) = generate_keypair().expect("keygen");
        let did = derive_did_from_public_key(&public);
        (secret, did)
    }

    /// A fresh registry in which `target` is already a known, previously-seen
    /// migration hash (Req 18.7): revocation tests that exercise the
    /// signature/threshold/halt logic must seed the known-hash set the way
    /// `prepare_migration` does in production.
    fn registry_that_has_seen(target: MigrationId) -> RevokedMigrationRegistry {
        let mut registry = RevokedMigrationRegistry::default();
        registry.record_known_migration(target);
        registry
    }

    #[test]
    fn revocation_with_sufficient_sigs_succeeds() {
        let target: MigrationId = [0x01u8; 32];
        let mut registry = registry_that_has_seen(target);
        let id1 = make_identity();
        let id2 = make_identity();

        let revocation = make_signed_revocation(target, &[id1, id2]);
        let halted = registry
            .apply_revocation(revocation, 2)
            .expect("apply_revocation should succeed");

        assert!(!halted, "no in-progress transform existed, so nothing was halted");
        assert!(registry.is_revoked(&target), "migration must be revoked");
        assert_eq!(registry.revocation_log().len(), 1);
    }

    #[test]
    fn revocation_below_threshold_returns_error() {
        let target: MigrationId = [0x02u8; 32];
        let mut registry = registry_that_has_seen(target);
        let id1 = make_identity();

        let revocation = make_signed_revocation(target, &[id1]);
        let result = registry.apply_revocation(revocation, 2); // need 2, got 1

        assert!(
            matches!(result, Err(TirBaseError::ThresholdNotMet { got: 1, need: 2 })),
            "should return ThresholdNotMet: {result:?}"
        );
        assert!(!registry.is_revoked(&target), "should not be revoked below threshold");
    }

    #[test]
    fn revocation_halts_in_progress() {
        let target: MigrationId = [0x03u8; 32];
        let mut registry = registry_that_has_seen(target);
        let id1 = make_identity();

        registry.mark_in_progress(target);
        assert!(registry.is_in_progress(&target));

        let revocation = make_signed_revocation(target, &[id1]);
        let halted = registry.apply_revocation(revocation, 1).expect("revoke");

        assert!(halted, "revoking an in-progress migration must report the halt");
        assert!(
            registry.is_in_progress(&target),
            "the in-progress marker must persist until the sandbox run exits \
             (finish_migration), keeping migrations serialised even when a run \
             is revoked mid-flight"
        );
        assert!(registry.is_revoked(&target));

        // Simulate the sandbox run exiting: the caller's finish path clears
        // the marker.
        registry.clear_in_progress(&target);
        assert!(!registry.is_in_progress(&target));
    }

    #[test]
    fn revoked_migration_stays_blocked() {
        let target: MigrationId = [0x04u8; 32];
        let mut registry = registry_that_has_seen(target);
        let id1 = make_identity();

        let revocation = make_signed_revocation(target, &[id1.clone()]);
        registry.apply_revocation(revocation, 1).expect("revoke");

        // Trying to revoke again: is_revoked returns true
        assert!(registry.is_revoked(&target));

        // The registry correctly tracks the audit log grows
        assert_eq!(registry.revocation_log().len(), 1);
    }

    #[test]
    fn invalid_signature_not_counted() {
        let target: MigrationId = [0x05u8; 32];
        let mut registry = registry_that_has_seen(target);

        let (_secret, did) = make_identity();
        // Use a different secret to sign (wrong key — signature should fail verify)
        let (wrong_secret, _) = generate_keypair().expect("keygen");
        let bad_sig = sign(&wrong_secret, &target).expect("sign with wrong key");

        let revocation = MigrationRevocationDelta {
            target_migration_id: target,
            signatures: vec![ManagerSignature {
                manager_did: did,
                signature: bad_sig,
            }],
            created_at: 0,
        };

        let result = registry.apply_revocation(revocation, 1);
        assert!(
            matches!(result, Err(TirBaseError::ThresholdNotMet { .. })),
            "invalid signature should not count toward threshold: {result:?}"
        );
    }

    #[test]
    fn revocation_for_unknown_migration_hash_is_rejected() {
        // Req 18.7: a revocation for a hash this device has never seen — even
        // one carrying threshold-valid Manager signatures — must be rejected,
        // not silently recorded.
        let mut registry = RevokedMigrationRegistry::default();
        let target: MigrationId = [0x06u8; 32];
        let id1 = make_identity();

        assert!(
            !registry.is_known_migration(&target),
            "the target hash was never seen by this device"
        );

        let revocation = make_signed_revocation(target, &[id1]);
        let result = registry.apply_revocation(revocation, 1);

        assert!(
            matches!(result, Err(TirBaseError::UnknownMigrationHash { .. })),
            "unknown-hash revocation must be rejected: {result:?}"
        );
        assert!(
            !registry.is_revoked(&target),
            "registry must stay un-poisoned when the target hash is unknown"
        );
        assert_eq!(
            registry.revocation_log().len(),
            0,
            "no audit entry may be appended for a rejected revocation"
        );
    }

    #[test]
    fn revocation_of_known_hash_succeeds_but_never_of_arbitrary_ones() {
        // The known-hash gate is target-specific: recording one hash as known
        // does not make any other hash revocable.
        let seen: MigrationId = [0x07u8; 32];
        let other: MigrationId = [0x08u8; 32];
        let mut registry = registry_that_has_seen(seen);

        let id1 = make_identity();
        let id2 = make_identity();

        // The seen hash revokes fine...
        let revocation = make_signed_revocation(seen, &[id1]);
        registry
            .apply_revocation(revocation, 1)
            .expect("revocation of a seen hash must succeed");
        assert!(registry.is_revoked(&seen));

        // ...but an arbitrary sibling hash is still rejected.
        let revocation_other = make_signed_revocation(other, &[id2]);
        let result = registry.apply_revocation(revocation_other, 1);
        assert!(
            matches!(result, Err(TirBaseError::UnknownMigrationHash { .. })),
            "an arbitrary hash must never be revocable just because another \
             hash was seen: {result:?}"
        );
        assert!(!registry.is_revoked(&other));
    }
}
