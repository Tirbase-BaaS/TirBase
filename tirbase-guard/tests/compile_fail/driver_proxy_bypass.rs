// Simulates bypassing admit() by calling the crate-private permit constructor.
// `ActuationPermit::new` is pub(crate) — not callable from an integration test
// (which is an external crate).
use tirbase_guard::ActuationPermit;
use tirbase_types::{FixedPointValue, TargetId, UNIT_PERCENT};

fn main() {
    let _ = ActuationPermit::new(
        TargetId::new("t"),
        "p".to_string(),
        FixedPointValue::new(1, 0, UNIT_PERCENT),
        [0u8; 16],
    );
    //~^ ERROR
}
