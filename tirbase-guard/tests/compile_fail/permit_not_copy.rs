// SPDX-License-Identifier: AGPL-3.0-only

use tirbase_guard::ActuationPermit;
fn assert_copy<T: Copy>() {}
fn main() {
    assert_copy::<ActuationPermit>();
 //~^ ERROR
}
