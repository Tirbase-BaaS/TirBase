//! SpatialDiversityTracker — enforces distinct squad/tunnel_sector tags in Quorum (Req 14.3, 14.5).
//!
//! The tracker records the spatial tags of receipts already counted toward Quorum,
//! and checks whether the current receipt set satisfies the deployment's diversity
//! requirements before Tier-1 durability can be declared.
//!
//! **Degradation path (Req 14.5):** when fewer distinct spatial tags are available
//! than the configured minimum, the tracker falls back to flat K-of-N receipt
//! collection and logs a `SpatialDiversityDegraded` warning.

#![allow(dead_code)]

use crate::errors::TirBaseError;
use std::collections::HashMap;

/// Tracks the spatial diversity of receipt issuers for one Delta set.
#[derive(Debug, Default, Clone)]
pub struct SpatialDiversityTracker {
    /// Map from spatial tag → number of receipts from peers with that tag.
    tag_counts: HashMap<String, usize>,
    /// Number of receipts from peers with no spatial tag attached.
    untagged: usize,
}

impl SpatialDiversityTracker {
    /// Create a new, empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a spatial tag from a newly verified receipt.
    ///
    /// Peers with `spatial_tag = None` are counted separately as "untagged".
    pub fn add(&mut self, spatial_tag: Option<&str>) {
        match spatial_tag {
            Some(tag) => *self.tag_counts.entry(tag.to_string()).or_insert(0) += 1,
            None => self.untagged += 1,
        }
    }

    /// Number of distinct *named* spatial tags seen so far.
    pub fn distinct_tag_count(&self) -> usize {
        self.tag_counts.len()
    }

    /// Total number of tagged receipts (excludes untagged).
    pub fn tagged_receipt_count(&self) -> usize {
        self.tag_counts.values().sum()
    }

    /// Check whether the current receipt set satisfies spatial diversity requirements.
    ///
    /// # Parameters
    ///
    /// * `min_tags` — minimum number of distinct spatial tags required across the K receipts.
    /// * `max_single_sector_fraction` — no single sector tag may account for more than this
    ///   fraction of `total_receipts` (e.g. `0.6` means no tag has more than 60% of receipts).
    /// * `total_receipts` — total number of verified receipts collected so far.
    ///
    /// # Behaviour
    ///
    /// - If `distinct_tag_count < min_tags`:
    ///   - Logs a `SpatialDiversityDegraded` warning (Req 14.5).
    ///   - Returns `Ok(true)` — falls back to **flat K-of-N** collection, meaning
    ///     the caller should accept the receipts without diversity enforcement.
    ///
    /// - Otherwise performs the full diversity check:
    ///   - `distinct_tag_count >= min_tags`, AND
    ///   - no single tag exceeds `max_single_sector_fraction * total_receipts`.
    ///   - Returns `Ok(true)` when both hold, `Ok(false)` otherwise.
    pub fn satisfies_diversity(
        &self,
        min_tags: usize,
        max_single_sector_fraction: f64,
        total_receipts: usize,
    ) -> Result<bool, TirBaseError> {
        let distinct = self.distinct_tag_count();

        // Degradation path: insufficient distinct tags available.
        if distinct < min_tags {
            // Log the degradation warning (Req 14.5).
            log_spatial_degradation(distinct, min_tags);
            // Fall back to flat K-of-N: accept without diversity enforcement.
            return Ok(true);
        }

        // Full diversity check: ensure no single sector exceeds the max fraction.
        if total_receipts == 0 {
            return Ok(false);
        }

        // A sector is over-represented if its fraction of the total exceeds the max.
        // We compute count / total > max_fraction, which is equivalent to:
        //   count > max_fraction * total
        // Using floating-point comparison directly avoids rounding ambiguity.
        for (_tag, &count) in &self.tag_counts {
            let fraction = count as f64 / total_receipts as f64;
            if fraction > max_single_sector_fraction {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Returns a snapshot of tag → count pairs for inspection and testing.
    pub fn tag_counts(&self) -> &HashMap<String, usize> {
        &self.tag_counts
    }

    /// Number of receipts from peers with no spatial tag.
    pub fn untagged_count(&self) -> usize {
        self.untagged
    }
}

/// Log a spatial diversity degradation warning.
///
/// In v1 this writes to stderr. Runtime degradation warnings are not yet routed
/// through the structured diagnostics channel (startup-only in v1; runtime routing is
/// deferred to a post-v1 task).
fn log_spatial_degradation(available: usize, required: usize) {
    eprintln!(
        "[durability] spatial diversity degraded: available={available}, required={required}. \
         Falling back to flat K-of-N receipt collection."
    );
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tracker(tags: &[Option<&str>]) -> SpatialDiversityTracker {
        let mut t = SpatialDiversityTracker::new();
        for tag in tags {
            t.add(*tag);
        }
        t
    }

    // ── distinct_tag_count ────────────────────────────────────────────────────

    #[test]
    fn distinct_tag_count_empty() {
        let t = SpatialDiversityTracker::new();
        assert_eq!(t.distinct_tag_count(), 0);
    }

    #[test]
    fn distinct_tag_count_multiple_peers_same_tag() {
        let t = make_tracker(&[Some("squad-alpha"), Some("squad-alpha"), Some("squad-alpha")]);
        assert_eq!(t.distinct_tag_count(), 1);
    }

    #[test]
    fn distinct_tag_count_two_different_tags() {
        let t = make_tracker(&[Some("squad-a"), Some("squad-b"), Some("squad-a")]);
        assert_eq!(t.distinct_tag_count(), 2);
    }

    #[test]
    fn untagged_peers_do_not_count_toward_distinct_tags() {
        let t = make_tracker(&[None, None, Some("squad-x")]);
        assert_eq!(t.distinct_tag_count(), 1);
        assert_eq!(t.untagged_count(), 2);
    }

    // ── satisfies_diversity — full check ────────────────────────────────────

    #[test]
    fn satisfies_diversity_passes_when_requirements_met() {
        // 3 receipts from 3 distinct tags, max fraction 0.5 → each tag has 1/3 ≤ 0.5
        let t = make_tracker(&[Some("sq-a"), Some("sq-b"), Some("sq-c")]);
        let result = t.satisfies_diversity(2, 0.5, 3);
        assert!(result.unwrap(), "3 distinct tags, no sector > 50%");
    }

    #[test]
    fn satisfies_diversity_fails_when_single_sector_exceeds_fraction() {
        // 3 receipts: sq-a has 2, sq-b has 1 → sq-a = 66.6% > 50%
        let t = make_tracker(&[Some("sq-a"), Some("sq-a"), Some("sq-b")]);
        let result = t.satisfies_diversity(2, 0.5, 3);
        assert!(!result.unwrap(), "sq-a exceeds 50% fraction limit");
    }

    #[test]
    fn satisfies_diversity_fails_when_not_enough_distinct_tags_after_degradation_fallback() {
        // When distinct < min_tags, degradation fallback returns Ok(true).
        // This test verifies the fallback path is reached and returns true.
        let t = make_tracker(&[Some("sq-a"), Some("sq-a")]);
        // min_tags=3 but only 1 distinct tag → degradation fallback
        let result = t.satisfies_diversity(3, 0.5, 2);
        assert!(
            result.unwrap(),
            "degradation fallback: flat K-of-N accepted"
        );
    }

    // ── degradation fallback ─────────────────────────────────────────────────

    #[test]
    fn degradation_fallback_when_zero_tags() {
        // All untagged peers — distinct_tag_count = 0 < min_tags = 2.
        let t = make_tracker(&[None, None, None]);
        let result = t.satisfies_diversity(2, 0.5, 3);
        // Fallback to flat K-of-N → returns Ok(true)
        assert!(result.unwrap(), "all untagged should trigger degradation fallback");
    }

    #[test]
    fn degradation_fallback_when_one_tag_fewer_than_min() {
        let t = make_tracker(&[Some("sq-a"), Some("sq-a")]);
        // min_tags=2, distinct=1 → degradation
        let result = t.satisfies_diversity(2, 0.5, 2);
        assert!(result.unwrap(), "degradation fallback for 1 < 2 distinct tags");
    }

    // ── edge cases ────────────────────────────────────────────────────────────

    #[test]
    fn satisfies_diversity_zero_total_receipts_returns_false() {
        let t = make_tracker(&[Some("sq-a"), Some("sq-b")]);
        // total_receipts=0 → can't form quorum, return false
        let result = t.satisfies_diversity(2, 0.5, 0);
        assert!(!result.unwrap());
    }

    #[test]
    fn satisfies_diversity_exactly_at_fraction_boundary_passes() {
        // 2 receipts from sq-a, 2 from sq-b → each is 50% of 4 total.
        // max_fraction=0.5 → 0.5 * 4 = 2.0 → max_allowed=2. sq-a count=2 ≤ 2. Passes.
        let t = make_tracker(&[Some("sq-a"), Some("sq-a"), Some("sq-b"), Some("sq-b")]);
        let result = t.satisfies_diversity(2, 0.5, 4);
        assert!(result.unwrap(), "exactly at fraction boundary should pass");
    }

    #[test]
    fn satisfies_diversity_one_over_fraction_boundary_fails() {
        // 3 receipts from sq-a, 1 from sq-b → sq-a = 75% of 4 total.
        // max_fraction=0.5 → max_allowed=2. sq-a count=3 > 2. Fails.
        let t = make_tracker(&[Some("sq-a"), Some("sq-a"), Some("sq-a"), Some("sq-b")]);
        let result = t.satisfies_diversity(2, 0.5, 4);
        assert!(!result.unwrap(), "one over fraction boundary should fail");
    }
}
