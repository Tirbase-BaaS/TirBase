//! Migration revocation — halt in-progress transforms, block future execution (Req 18.5–18.7).

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
    /// Append-only audit log of all revocation events.
    revocation_log: Vec<RevocationRecord>,
    /// Migrations that are currently in-progress (sandbox running).
    /// On revocation these must be halted (Req 18.6).
    in_progress: HashSet<MigrationId>,
}

impl RevokedMigrationRegistry {
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
    /// 1. Verify each Manager DID signature over `target_migration_id`.
    /// 2. Check that at least `threshold_m` distinct, valid signatures are present.
    /// 3. If in-progress: mark as halted (caller must check `is_revoked` before executing).
    /// 4. Permanently block the migration ID.
    /// 5. Append a RevocationRecord to the audit log.
    pub fn apply_revocation(
        &mut self,
        revocation: MigrationRevocationDelta,
        threshold_m: usize,
    ) -> Result<(), TirBaseError> {
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
        // The `in_progress` flag is checked by the sandbox caller; clearing it
        // here signals that the sandbox must be treated as halted.  The actual
        // thread/future interruption is the caller's responsibility (epoch
        // interrupt on wasmtime side).
        if self.in_progress.contains(&revocation.target_migration_id) {
            eprintln!(
                "[revocation] Halting in-progress migration {:?}",
                revocation.target_migration_id
            );
            self.in_progress.remove(&revocation.target_migration_id);
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

        Ok(())
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

    #[test]
    fn revocation_with_sufficient_sigs_succeeds() {
        let mut registry = RevokedMigrationRegistry::default();
        let target: MigrationId = [0x01u8; 32];
        let id1 = make_identity();
        let id2 = make_identity();

        let revocation = make_signed_revocation(target, &[id1, id2]);
        registry.apply_revocation(revocation, 2).expect("apply_revocation should succeed");

        assert!(registry.is_revoked(&target), "migration must be revoked");
        assert_eq!(registry.revocation_log().len(), 1);
    }

    #[test]
    fn revocation_below_threshold_returns_error() {
        let mut registry = RevokedMigrationRegistry::default();
        let target: MigrationId = [0x02u8; 32];
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
        let mut registry = RevokedMigrationRegistry::default();
        let target: MigrationId = [0x03u8; 32];
        let id1 = make_identity();

        registry.mark_in_progress(target);
        assert!(registry.is_in_progress(&target));

        let revocation = make_signed_revocation(target, &[id1]);
        registry.apply_revocation(revocation, 1).expect("revoke");

        assert!(!registry.is_in_progress(&target), "in-progress must be cleared on revocation");
        assert!(registry.is_revoked(&target));
    }

    #[test]
    fn revoked_migration_stays_blocked() {
        let mut registry = RevokedMigrationRegistry::default();
        let target: MigrationId = [0x04u8; 32];
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
        let mut registry = RevokedMigrationRegistry::default();
        let target: MigrationId = [0x05u8; 32];

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
}
