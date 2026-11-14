// SPDX-License-Identifier: AGPL-3.0-only

use tirbase_guard::ActuationPermit;
fn main() {
    let _ = ActuationPermit::default();
 //~^ ERROR
}
