//! Tier-1 quorum formation — K-of-N receipts with spatial diversity (Req 14.2–14.3).
//!
//! A Delta set is Tier-1 durable when K valid `DurabilityReceipt`s have been
//! collected, spanning the required spatial diversity (distinct squad/tunnel_sector
//! tags with no single sector exceeding the configured max fraction).
//!
//! Receipt verification (Ed25519 signature + state-hash) is handled by
//! `durability::receipt::verify_receipt` before receipts reach the quorum tracker.
//! The quorum tracker only needs to count valid receipts and check diversity.
//!
//! # Req 14.3 default diversity rule (Subphase 4.4)
//!
//! A `spatial_diversity_min` of `0` in [`QuorumConfig`] is the *unconfigured*
//! marker (the `DeploymentConfig` default).  It is **not** enforced as "require
//! 0 distinct tags": instead the tracker resolves the Req 14.3 default rule
//! `min(K, distinct tags available)` at runtime (see
//! [`Tier1QuorumTracker::effective_min_distinct`]).  Because the tracker only
//! learns spatial tags from verified receipts, "distinct tags available" is the
//! distinct tag set among the receipts collected so far — the codebase's
//! documented model (design.md:914 reconciles the pool-tag model to the
//! observed-tag model; the candidate pool itself carries no tag registry).

#![allow(dead_code)]

use crate::durability::receipt::DurabilityReceipt;
use crate::durability::spatial::SpatialDiversityTracker;
use crate::errors::TirBaseError;
use std::collections::HashSet;

/// Configuration for Tier-1 quorum formation.
#[derive(Debug, Clone)]
pub struct QuorumConfig {
    /// K receipts required to declare Tier-1 durability (Req 14.2).
    pub k: usize,
    /// N total candidate peers in the pool (Req 14.2).
    pub n: usize,
    /// Minimum number of distinct spatial tags required across the K receipts (Req 14.3).
    ///
    /// `0` is the *unconfigured* marker (the `DeploymentConfig` default): the
    /// tracker then applies Req 14.3's default rule `min(k, distinct tags
    /// available)` at runtime (see [`Tier1QuorumTracker::effective_min_distinct`])
    /// rather than enforcing a raw 0-distinct minimum.  An explicit value `> 0`
    /// is enforced as configured, with the Req 14.5 degradation fallback (flat
    /// K-of-N + warning) when fewer distinct tags are available.
    pub spatial_diversity_min: usize,
    /// Maximum fraction of Quorum receipts from any single spatial tag (Req 14.3).
    /// E.g. `0.5` means no single sector may provide more than 50% of the K receipts.
    pub max_single_sector_fraction: f64,
}

impl Default for QuorumConfig {
    fn default() -> Self {
        Self {
            k: 3,
            n: 5,
            spatial_diversity_min: 2,
            max_single_sector_fraction: 0.6,
        }
    }
}

/// Tracks receipt collection for a specific Delta set state-hash and determines when
/// Tier-1 durability is achieved (Req 14.2).
///
/// Receipts must be **pre-verified** (signature + state-hash match) before being
/// added here. The tracker only handles counting and diversity enforcement.
#[derive(Debug, Clone)]
pub struct Tier1QuorumTracker {
    config: QuorumConfig,
    /// Verified receipts collected so far.
    receipts: Vec<DurabilityReceipt>,
    /// Set of issuer DIDs to prevent double-counting the same peer.
    seen_issuers: HashSet<String>,
    /// Spatial diversity tracker.
    spatial: SpatialDiversityTracker,
    /// Whether Tier-1 has already been achieved.
    tier1_achieved: bool,
}

impl Tier1QuorumTracker {
    /// Create a new tracker for the given quorum configuration.
    pub fn new(config: QuorumConfig) -> Self {
        Self {
            config,
            receipts: Vec::new(),
            seen_issuers: HashSet::new(),
            spatial: SpatialDiversityTracker::new(),
            tier1_achieved: false,
        }
    }

    /// Add a **pre-verified** receipt to the tracker and check if Tier-1 quorum is now achieved.
    ///
    /// Returns:
    /// - `Ok(true)`  — this receipt caused Tier-1 durability to be reached.
    /// - `Ok(false)` — receipt accepted; quorum not yet achieved.
    ///
    /// Receipts from the same issuer DID are deduplicated (the second and subsequent
    /// receipts from the same peer are silently ignored).
    pub fn add_receipt(&mut self, receipt: DurabilityReceipt) -> Result<bool, TirBaseError> {
        // The spatial diversity tag defaults to the receipt's own declared tag.
        self.add_receipt_with_tag(receipt, None)
    }

    /// Add a **pre-verified** receipt whose diversity tag is supplied explicitly.
    ///
    /// `diversity_tag` is the spatial tag recorded toward Spatial_Diversity.  When
    /// `None`, the receipt's own declared `spatial_tag` is used.  The Durability
    /// Subsystem passes an explicit tag when Anchor_Attested_Location is enabled
    /// in BeaconAttested mode: there the tag is the **beacon-verified location
    /// claim** of the receipt's token, never the (spoofable) self-declared squad
    /// tag (Req 15.2).  `pub(crate)`: only the Durability Subsystem drives the
    /// anchor mode; external callers use [`Self::add_receipt`].
    pub(crate) fn add_receipt_with_tag(
        &mut self,
        receipt: DurabilityReceipt,
        diversity_tag: Option<&str>,
    ) -> Result<bool, TirBaseError> {
        // Idempotency: ignore duplicate receipts from the same issuer.
        if self.seen_issuers.contains(&receipt.issuer_did) {
            return Ok(self.tier1_achieved);
        }

        // Record the spatial tag.
        self.spatial.add(diversity_tag.or(receipt.spatial_tag.as_deref()));

        // Mark issuer as seen.
        self.seen_issuers.insert(receipt.issuer_did.clone());
        self.receipts.push(receipt);

        // Check if quorum is achieved.
        if !self.tier1_achieved && self.receipts.len() >= self.config.k {
            let diversity_ok = self.spatial.satisfies_diversity(
                self.effective_min_distinct(),
                self.config.max_single_sector_fraction,
                self.receipts.len(),
            )?;

            if diversity_ok {
                self.tier1_achieved = true;
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Whether Tier-1 durability has been achieved for this Delta set.
    pub fn is_tier1(&self) -> bool {
        self.tier1_achieved
    }

    /// Number of verified receipts collected so far.
    pub fn receipt_count(&self) -> usize {
        self.receipts.len()
    }

    /// Access the quorum configuration.
    pub fn config(&self) -> &QuorumConfig {
        &self.config
    }

    /// Access the spatial diversity tracker (for introspection / testing).
    pub fn spatial(&self) -> &SpatialDiversityTracker {
        &self.spatial
    }

    /// The effective minimum-distinct-tag requirement for the receipts
    /// collected so far (Req 14.3).
    ///
    /// - Configured (`spatial_diversity_min > 0`): returned verbatim.
    /// - Unconfigured (`0` marker): Req 14.3's default rule —
    ///   `min(K, distinct tags available)`, where "available" is the distinct
    ///   spatial tags among the receipts collected so far (the tracker's only
    ///   knowledge of tag availability).  The rule never demands more distinct
    ///   tags than actually exist, so an unconfigured deployment is governed by
    ///   the `max_single_sector_fraction` cap rather than a min-distinct floor.
    ///
    /// `pub(crate)`: introspection for in-crate callers/tests; quorum diversity
    /// is internal policy, not external API surface.
    pub(crate) fn effective_min_distinct(&self) -> usize {
        let configured = self.config.spatial_diversity_min;
        if configured == 0 {
            self.config.k.min(self.spatial.distinct_tag_count())
        } else {
            configured
        }
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crdt::delta::Ed25519Signature;
    use crate::durability::receipt::{receipt_signing_payload, DurabilityReceipt};
    use crate::identity::keypair::{generate_keypair, sign};
    use uuid::Uuid;

    /// Helper: build a properly-signed DurabilityReceipt.
    fn make_receipt(
        state_hash: [u8; 32],
        secret_key: &[u8; 32],
        issuer_did: &str,
        spatial_tag: Option<&str>,
    ) -> DurabilityReceipt {
        let id = Uuid::now_v7();
        let payload = receipt_signing_payload(&state_hash, &id);
        let sig = sign(secret_key, &payload).expect("sign receipt");
        DurabilityReceipt {
            id,
            state_hash,
            issuer_did: issuer_did.to_string(),
            issuer_signature: sig,
            spatial_tag: spatial_tag.map(|s| s.to_string()),
            beacon_token: None,
            issued_at: 0,
        }
    }

    /// QuorumConfig with K=3, spatial_diversity_min=2, max_fraction=0.6.
    fn config_k3_div2() -> QuorumConfig {
        QuorumConfig {
            k: 3,
            n: 5,
            spatial_diversity_min: 2,
            max_single_sector_fraction: 0.6,
        }
    }

    // ── Quorum forms at exactly K receipts ───────────────────────────────────

    #[test]
    fn quorum_achieved_at_k_receipts_with_diversity() {
        let state_hash = [0xAA; 32];
        let mut tracker = Tier1QuorumTracker::new(config_k3_div2());

        for i in 0..3u8 {
            let (secret, _) = generate_keypair().unwrap();
            let did = format!("did:key:peer{i}");
            // Alternate tags: sq-a, sq-b, sq-a → distinct=2, max_count=2 out of 3 ≈ 67% ≤ 60%?
            // Actually 2/3 ≈ 66.6% which is > 60%. Use sq-a, sq-b, sq-c instead.
            let tag = format!("squad-{}", (b'a' + i) as char);
            let receipt = make_receipt(state_hash, &secret, &did, Some(&tag));
            let result = tracker.add_receipt(receipt).unwrap();
            if i < 2 {
                assert!(!result, "quorum not yet at receipt {i}");
            } else {
                assert!(result, "quorum should be achieved at receipt 3");
            }
        }
        assert!(tracker.is_tier1());
    }

    #[test]
    fn below_k_receipts_does_not_achieve_tier1() {
        let state_hash = [0xBB; 32];
        let mut tracker = Tier1QuorumTracker::new(config_k3_div2());

        for i in 0..2u8 {
            let (secret, _) = generate_keypair().unwrap();
            let did = format!("did:key:peer{i}");
            let tag = format!("sq-{}", (b'a' + i) as char);
            let receipt = make_receipt(state_hash, &secret, &did, Some(&tag));
            let achieved = tracker.add_receipt(receipt).unwrap();
            assert!(!achieved, "should not achieve Tier-1 with only {i} receipts");
        }
        assert!(!tracker.is_tier1());
    }

    // ── Spatial diversity enforcement ─────────────────────────────────────────

    #[test]
    fn spatial_diversity_single_sector_excess_prevents_tier1() {
        // K=3, max_fraction=0.5 → max_allowed = ceil(0.5 * 3) = 2.
        let cfg = QuorumConfig {
            k: 3,
            n: 5,
            spatial_diversity_min: 1,         // only 1 distinct tag required
            max_single_sector_fraction: 0.5,  // 50% max per sector
        };
        let state_hash = [0xCC; 32];
        let mut tracker = Tier1QuorumTracker::new(cfg);

        // 3 receipts all from "sector-x" → 100% in one sector, exceeds 50%.
        for i in 0..3u8 {
            let (secret, _) = generate_keypair().unwrap();
            let did = format!("did:key:peer{i}");
            let receipt = make_receipt(state_hash, &secret, &did, Some("sector-x"));
            let achieved = tracker.add_receipt(receipt).unwrap();
            // satisfies_diversity: distinct=1 >= min_tags=1, but sector-x count > max_allowed.
            assert!(!achieved, "all same sector must not achieve Tier-1");
        }
        assert!(!tracker.is_tier1());
    }

    #[test]
    fn spatial_diversity_fallback_to_flat_kofn_when_insufficient_tags() {
        // K=3, spatial_diversity_min=3, but only 1 distinct tag is available.
        // Degradation fallback → flat K-of-N → Tier-1 should be achieved.
        let cfg = QuorumConfig {
            k: 3,
            n: 5,
            spatial_diversity_min: 3,
            max_single_sector_fraction: 1.0, // irrelevant in fallback
        };
        let state_hash = [0xDD; 32];
        let mut tracker = Tier1QuorumTracker::new(cfg);

        let mut achieved_at_k = false;
        for i in 0..3u8 {
            let (secret, _) = generate_keypair().unwrap();
            let did = format!("did:key:fallback{i}");
            // All same tag → distinct=1 < min=3 → degradation fallback → flat K-of-N accepted.
            let receipt = make_receipt(state_hash, &secret, &did, Some("only-sector"));
            let achieved = tracker.add_receipt(receipt).unwrap();
            if i == 2 {
                achieved_at_k = achieved;
            }
        }
        assert!(achieved_at_k, "degradation fallback should allow Tier-1 via flat K-of-N");
        assert!(tracker.is_tier1());
    }

    // ── Req 14.3 default diversity rule (Subphase 4.4) ────────────────────────
    //
    // A `spatial_diversity_min` of 0 is the *unconfigured* marker: the tracker
    // must resolve it to the Req 14.3 default `min(K, distinct tags available)`
    // at runtime, not enforce a raw 0-distinct minimum.

    #[test]
    fn unconfigured_min_resolves_to_min_of_k_and_available_distinct() {
        // K=3, unconfigured (0) → effective min tracks min(K, distinct seen).
        let cfg = QuorumConfig {
            k: 3,
            n: 5,
            spatial_diversity_min: 0,
            max_single_sector_fraction: 1.0,
        };
        let mut tracker = Tier1QuorumTracker::new(cfg);

        // Empty tracker: no distinct tags available yet → min(3, 0) = 0.
        assert_eq!(tracker.effective_min_distinct(), 0);

        // One distinct tag seen → min(3, 1) = 1.
        add_tagged(&mut tracker, "sq-a");
        assert_eq!(tracker.effective_min_distinct(), 1);

        // Two distinct tags seen → min(3, 2) = 2.
        add_tagged(&mut tracker, "sq-b");
        assert_eq!(tracker.effective_min_distinct(), 2);

        // Three distinct tags seen → min(3, 3) = 3 (capped at K).
        add_tagged(&mut tracker, "sq-c");
        assert_eq!(tracker.effective_min_distinct(), 3);

        // A fourth distinct tag cannot raise the requirement above K.
        add_tagged(&mut tracker, "sq-d");
        assert_eq!(tracker.effective_min_distinct(), 3, "min-distinct caps at K");
    }

    #[test]
    fn configured_min_is_used_verbatim_not_recomputed() {
        // Explicit min=2 must NOT be recomputed as min(K, distinct) or as 0.
        let cfg = QuorumConfig {
            k: 3,
            n: 5,
            spatial_diversity_min: 2,
            max_single_sector_fraction: 1.0,
        };
        let mut tracker = Tier1QuorumTracker::new(cfg);

        add_tagged(&mut tracker, "sq-a");
        add_tagged(&mut tracker, "sq-b");
        assert_eq!(tracker.effective_min_distinct(), 2);

        // Even when more than 2 tags are available the configured min holds.
        add_tagged(&mut tracker, "sq-c");
        assert_eq!(tracker.effective_min_distinct(), 2);
    }

    #[test]
    fn unconfigured_min_with_cap_off_accepts_single_sector_deployment() {
        // K=3, unconfigured min, cap 1.0 (no single-sector limit): a deployment
        // whose receipts span only 1 distinct tag needs min(3, 1) = 1 distinct
        // tag — met — so Tier-1 forms at K receipts.  The default rule must not
        // demand more diversity than is available.
        let cfg = QuorumConfig {
            k: 3,
            n: 5,
            spatial_diversity_min: 0,
            max_single_sector_fraction: 1.0,
        };
        let state_hash = [0xAB; 32];
        let mut tracker = Tier1QuorumTracker::new(cfg);

        let mut achieved = false;
        for i in 0..3u8 {
            let (secret, _) = generate_keypair().unwrap();
            let did = format!("did:key:single-sector{i}");
            let receipt = make_receipt(state_hash, &secret, &did, Some("only-sector"));
            let result = tracker.add_receipt(receipt).unwrap();
            if i == 2 {
                achieved = result;
            }
        }
        assert!(achieved, "default rule must not block a single-sector quorum when the cap allows it");
        assert!(tracker.is_tier1());
    }

    #[test]
    fn unconfigured_min_keeps_fraction_cap_enforcement() {
        // The default-rule resolution only governs the min-distinct leg; the
        // Req 14.3 `max_single_sector_fraction` cap must still bind.  K=3,
        // unconfigured min, cap 0.5: two sq-a receipts (66% of 3) exceed the
        // cap → no Tier-1 at 3 receipts; a third distinct tag dilutes sq-a to
        // exactly 50% → Tier-1.
        let cfg = QuorumConfig {
            k: 3,
            n: 5,
            spatial_diversity_min: 0,
            max_single_sector_fraction: 0.5,
        };
        let state_hash = [0xCD; 32];
        let mut tracker = Tier1QuorumTracker::new(cfg);

        // Receipt 1: sq-a. Receipt 2: sq-a (2/2 = 100% > 50%, and 2 < K anyway).
        // Receipt 3: sq-b → sq-a = 2/3 ≈ 66.7% > 50% → blocked.
        let mut achieved_at_3 = false;
        for (i, tag) in ["sq-a", "sq-a", "sq-b"].iter().enumerate() {
            let (secret, _) = generate_keypair().unwrap();
            let did = format!("did:key:cap{i}");
            let receipt = make_receipt(state_hash, &secret, &did, Some(tag));
            let result = tracker.add_receipt(receipt).unwrap();
            if i == 2 {
                achieved_at_3 = result;
            }
        }
        assert!(!achieved_at_3, "sq-a at 66% must exceed the 50% cap");
        assert!(!tracker.is_tier1());

        // Receipt 4 from sq-c: sq-a = 2/4 = 50% ≤ 50%, distinct = 3 ≥
        // min(3, 3) → Tier-1.
        let (secret, _) = generate_keypair().unwrap();
        let receipt = make_receipt(state_hash, &secret, "did:key:cap3", Some("sq-c"));
        let achieved = tracker.add_receipt(receipt).unwrap();
        assert!(achieved, "dilution below the cap must allow Tier-1");
        assert!(tracker.is_tier1());
    }

    /// Helper: record a tagged receipt under the tracker's default rule.
    fn add_tagged(tracker: &mut Tier1QuorumTracker, tag: &str) {
        let (secret, _) = generate_keypair().unwrap();
        let did = format!("did:key:eff-{}-{}", tag, uuid::Uuid::new_v4());
        let receipt = make_receipt([0u8; 32], &secret, &did, Some(tag));
        // add_receipt may return Ok(true) once ≥ K distinct tags are in —
        // irrelevant here; the tag count is what matters.
        let _ = tracker.add_receipt(receipt).unwrap();
    }

    // ── Duplicate issuer deduplication ────────────────────────────────────────

    #[test]
    fn duplicate_issuer_receipt_is_ignored() {
        let state_hash = [0xEE; 32];
        let mut tracker = Tier1QuorumTracker::new(QuorumConfig {
            k: 2,
            n: 5,
            spatial_diversity_min: 1,
            max_single_sector_fraction: 1.0,
        });

        let (secret, _) = generate_keypair().unwrap();
        let did = "did:key:same-peer";

        // Submit same issuer twice.
        let r1 = make_receipt(state_hash, &secret, did, Some("sq-a"));
        let r2 = make_receipt(state_hash, &secret, did, Some("sq-a"));
        tracker.add_receipt(r1).unwrap();
        tracker.add_receipt(r2).unwrap(); // duplicate — ignored

        // Only 1 unique issuer counted → K=2 not reached.
        assert_eq!(tracker.receipt_count(), 1);
        assert!(!tracker.is_tier1());
    }

    // ── receipt_count ─────────────────────────────────────────────────────────

    #[test]
    fn receipt_count_increases_with_unique_issuers() {
        let state_hash = [0xFF; 32];
        let mut tracker = Tier1QuorumTracker::new(QuorumConfig::default());
        assert_eq!(tracker.receipt_count(), 0);

        for i in 0..3u8 {
            let (secret, _) = generate_keypair().unwrap();
            let did = format!("did:key:cnt{i}");
            let receipt = make_receipt(state_hash, &secret, &did, None);
            tracker.add_receipt(receipt).unwrap();
            assert_eq!(tracker.receipt_count(), (i + 1) as usize);
        }
    }

    // ── tier1 is sticky ───────────────────────────────────────────────────────

    #[test]
    fn tier1_achieved_is_sticky_after_first_confirmation() {
        let state_hash = [0x11; 32];
        let cfg = QuorumConfig {
            k: 2,
            n: 5,
            spatial_diversity_min: 1,
            max_single_sector_fraction: 1.0,
        };
        let mut tracker = Tier1QuorumTracker::new(cfg);

        for i in 0..2u8 {
            let (secret, _) = generate_keypair().unwrap();
            let did = format!("did:key:sticky{i}");
            let receipt = make_receipt(state_hash, &secret, &did, Some("sq-a"));
            tracker.add_receipt(receipt).unwrap();
        }
        assert!(tracker.is_tier1());

        // Adding more receipts doesn't change is_tier1.
        let (secret, _) = generate_keypair().unwrap();
        let receipt = make_receipt(state_hash, &secret, "did:key:extra", Some("sq-b"));
        tracker.add_receipt(receipt).unwrap();
        assert!(tracker.is_tier1());
    }
}
