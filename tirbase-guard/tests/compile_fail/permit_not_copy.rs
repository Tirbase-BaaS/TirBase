use tirbase_guard::ActuationPermit;
fn assert_copy<T: Copy>() {}
fn main() {
    assert_copy::<ActuationPermit>();
    //~^ ERROR
}
