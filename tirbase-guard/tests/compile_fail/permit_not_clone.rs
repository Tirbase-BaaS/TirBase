// SPDX-License-Identifier: AGPL-3.0-only

use tirbase_guard::ActuationPermit;
fn assert_clone<T: Clone>() {}
fn main() {
    assert_clone::<ActuationPermit>();
 //~^ ERROR
}
