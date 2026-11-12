// Simulates a local admin ingress handler attempting to forge an ActuationPermit.
use tirbase_guard::ActuationPermit;
use tirbase_types::{FixedPointValue, TargetId, UNIT_PERCENT};

fn main() {
    let _ = ActuationPermit {
        target_id: TargetId::new("t"),
        param: "p".to_string(),
        value: FixedPointValue::new(1, 0, UNIT_PERCENT),
        entry_id: [0u8; 16],
        _sealed: (),
    };
 //~^ ERROR
}
