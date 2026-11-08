use tirbase_guard::ActuationPermit;
fn assert_clone<T: Clone>() {}
fn main() {
    assert_clone::<ActuationPermit>();
    //~^ ERROR
}
