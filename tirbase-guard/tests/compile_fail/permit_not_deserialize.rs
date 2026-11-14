// SPDX-License-Identifier: AGPL-3.0-only

use tirbase_guard::ActuationPermit;
fn assert_de<T: serde::de::DeserializeOwned>() {}
fn main() {
    assert_de::<ActuationPermit>();
 //~^ ERROR
}
