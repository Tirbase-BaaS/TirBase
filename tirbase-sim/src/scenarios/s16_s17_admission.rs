//! Scenarios S16 and S17 — fleet fan-out blast radius and cross-role attempts.
//!
//! S16 drives the per-issuer rate limiter in the production admission pipeline:
//! a bulk burst beyond the quota is rejected with `RateLimit` while the first
//! command in the burst is accepted.  S17 presents a validly signed token whose
//! role is not `CommandIssuer`; Stage 4 must derive the role from the token (not
//! `cmd.role`) and reject with `ScopeViolation`.

use tirbase_core::auth::command_token::create_command_token;
use tirbase_core::traits::KeyProvider;
use tirbase_guard::admit::AdmitRejection;
use tirbase_guard::AdmitError;

use super::guard_harness::AdversaryFixture;

fn assert_rejection(
    result: Result<(), AdmitError>,
    expected: AdmitRejection,
    scenario: &str,
) -> Result<(), String> {
    match result {
        Err(AdmitError::Pipeline { category, .. }) if category == expected => Ok(()),
        Err(other) => Err(format!(
            "{scenario} FAIL: expected {expected:?}, got {other:?}"
        )),
        Ok(()) => Err(format!("{scenario} FAIL: command was accepted")),
    }
}

/// S16 — the per-issuer write quota bounds a bulk fleet-wide burst.
pub fn run_s16(seed: u64) -> Result<(), String> {
    let fixture = AdversaryFixture::new("pump-s16", "speed", false)?;
    fixture.pipeline.set_issuer_rps(1);

    let burst = 2 + (seed % 3) as usize;
    let mut accepted = 0usize;
    let mut rate_limited = 0usize;
    for index in 0..burst {
        // Distinct targets are not modelled by this single-target fixture, so
        // the burst represents a compromised cloud endpoint fanning commands
        // out through one issuer identity.  The quota is per issuer.
        let command = fixture.command(10 + index as i64, index as u8, index as u64 + 1)?;
        match fixture.admit(&command) {
            Ok(()) => accepted += 1,
            Err(AdmitError::Pipeline {
                category: AdmitRejection::RateLimit,
                ..
            }) => {
                rate_limited += 1
            }
            Err(other) => {
                return Err(format!("S16 FAIL: unexpected rejection: {other:?}"));
            }
        }
    }
    if accepted != 1 {
        return Err(format!(
            "S16 FAIL: expected exactly one command through a 1 cmd/s quota, accepted={accepted}"
        ));
    }
    if rate_limited != burst - 1 {
        return Err(format!(
            "S16 FAIL: expected {} rate-limited commands, got {rate_limited}",
            burst - 1
        ));
    }
    Ok(())
}

/// S17 — a token for a privileged role cannot be used on the command path.
pub fn run_s17(seed: u64) -> Result<(), String> {
    let fixture = AdversaryFixture::new("pump-s17", "speed", false)?;
    let privileged_token = create_command_token(
        fixture.issuer.did(),
        "TimeAnchor",
        3_600,
        fixture.target.as_str(),
        &fixture.param,
        &[],
        &fixture.ca_secret,
    )
    .map_err(|error| format!("S17 privileged token: {error:?}"))?;

    let command = fixture.command(10 + (seed % 5) as i64, 1, 1)?;
    assert_rejection(
        fixture.admit_with_token(&command, &privileged_token),
        AdmitRejection::ScopeViolation,
        "S17",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s16_fleet_fanout_rate_limited() {
        run_s16(1).expect("S16");
    }

    #[test]
    fn s17_cross_role_rejected() {
        run_s17(1).expect("S17");
    }
}
