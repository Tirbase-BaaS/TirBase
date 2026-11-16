// SPDX-License-Identifier: Apache-2.0

//! On-call rotation arithmetic.
//!
//! A rotation names a role and an escalation level and cycles its members every
//! `period_secs` from `start_est`. The answer is a pure function of the schedule
//! and the instant asked about, so routing a historical alert (or replaying a
//! test) gives the same recipient as it did at the time.

use std::collections::BTreeSet;

/// One rotating duty: who is on call for `role` at `level`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotation {
    /// Role this rotation covers, for example `cold-chain-oncall`.
    pub role: String,
    /// Escalation level this rotation serves (1 is the first page).
    pub level: u32,
    /// When member 0 took over (Unix seconds).
    pub start_est: i64,
    /// How long each member stays on call.
    pub period_secs: i64,
    /// Members in handover order. Addresses are mailboxes or plugin handles.
    pub members: Vec<String>,
}

impl Rotation {
    /// Who is on call at `at_est`, if anyone is.
    pub fn on_call(&self, at_est: i64) -> Option<&str> {
        if self.members.is_empty() || self.period_secs <= 0 {
            return None;
        }
        let elapsed = at_est.saturating_sub(self.start_est);
        let slot = elapsed.div_euclid(self.period_secs);
        let index = slot.rem_euclid(self.members.len() as i64) as usize;
        self.members.get(index).map(String::as_str)
    }
}

/// The rotations a deployment runs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OnCallSchedule {
    rotations: Vec<Rotation>,
}

impl OnCallSchedule {
    /// Validate and assemble a schedule.
    ///
    /// Every rotation needs members, a positive period and a unique
    /// `(role, level)` pair — two rotations for the same duty would make routing
    /// ambiguous.
    pub fn new(rotations: Vec<Rotation>) -> Result<Self, String> {
        let mut seen = BTreeSet::new();
        for rotation in &rotations {
            if rotation.role.trim().is_empty() {
                return Err("on-call rotation needs a role".to_string());
            }
            if rotation.level == 0 {
                return Err(format!(
                    "on-call rotation for role {:?} has level 0; levels start at 1",
                    rotation.role
                ));
            }
            if rotation.period_secs <= 0 {
                return Err(format!(
                    "on-call rotation for role {:?} needs a positive period",
                    rotation.role
                ));
            }
            if rotation.members.is_empty() {
                return Err(format!(
                    "on-call rotation for role {:?} has no members",
                    rotation.role
                ));
            }
            if rotation
                .members
                .iter()
                .any(|member| member.trim().is_empty())
            {
                return Err(format!(
                    "on-call rotation for role {:?} has an empty member",
                    rotation.role
                ));
            }
            if !seen.insert((rotation.role.clone(), rotation.level)) {
                return Err(format!(
                    "duplicate on-call rotation for role {:?} at level {}",
                    rotation.role, rotation.level
                ));
            }
        }
        Ok(Self { rotations })
    }

    /// Who is on call for `role` at `level` at `at_est`.
    pub fn on_call(&self, role: &str, level: u32, at_est: i64) -> Option<&str> {
        self.rotations
            .iter()
            .find(|rotation| rotation.role == role && rotation.level == level)
            .and_then(|rotation| rotation.on_call(at_est))
    }

    /// `true` when no rotation is configured.
    pub fn is_empty(&self) -> bool {
        self.rotations.is_empty()
    }

    /// The configured rotations.
    pub fn rotations(&self) -> &[Rotation] {
        &self.rotations
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rotation() -> Rotation {
        Rotation {
            role: "cold-chain-oncall".to_string(),
            level: 1,
            start_est: 1_000,
            period_secs: 3_600,
            members: vec![
                "ana@example.com".to_string(),
                "bo@example.com".to_string(),
                "cy@example.com".to_string(),
            ],
        }
    }

    #[test]
    fn the_rotation_cycles_from_its_start_and_wraps_backwards() {
        let rotation = rotation();
        assert_eq!(rotation.on_call(1_000), Some("ana@example.com"));
        assert_eq!(rotation.on_call(4_599), Some("ana@example.com"));
        assert_eq!(rotation.on_call(4_600), Some("bo@example.com"));
        assert_eq!(rotation.on_call(8_200), Some("cy@example.com"));
        // A time before the rotation started still lands on a member.
        assert_eq!(rotation.on_call(1_000 - 1), Some("cy@example.com"));
        assert_eq!(rotation.on_call(1_000 - 4_600), Some("bo@example.com"));
    }

    #[test]
    fn schedules_reject_ambiguous_or_empty_rotations() {
        let mut second = rotation();
        second.level = 2;
        second.members = vec!["lead@example.com".to_string()];
        let schedule = OnCallSchedule::new(vec![rotation(), second]).expect("schedule");
        assert_eq!(
            schedule.on_call("cold-chain-oncall", 1, 4_600),
            Some("bo@example.com")
        );
        assert_eq!(
            schedule.on_call("cold-chain-oncall", 2, 4_600),
            Some("lead@example.com")
        );
        assert_eq!(schedule.on_call("other-role", 1, 4_600), None);

        assert!(OnCallSchedule::new(vec![rotation(), rotation()]).is_err());
        let mut empty = rotation();
        empty.members.clear();
        assert!(OnCallSchedule::new(vec![empty]).is_err());
        let mut zero_period = rotation();
        zero_period.period_secs = 0;
        assert!(OnCallSchedule::new(vec![zero_period]).is_err());
        let mut level_zero = rotation();
        level_zero.level = 0;
        assert!(OnCallSchedule::new(vec![level_zero]).is_err());
    }
}
