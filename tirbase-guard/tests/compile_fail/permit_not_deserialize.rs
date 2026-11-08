use tirbase_guard::ActuationPermit;
fn assert_de<T: serde::de::DeserializeOwned>() {}
fn main() {
    assert_de::<ActuationPermit>();
    //~^ ERROR
}
