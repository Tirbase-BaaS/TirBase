//! Instruction-count benchmarks for CI gating (CLAIM-40.3, PV-15.3).

use automerge::transaction::Transactable;
use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use std::hint::black_box;

#[library_benchmark]
fn delta_apply_save_load() -> usize {
    let mut doc = automerge::AutoCommit::new();
    doc.put(automerge::ROOT, "k", "v").unwrap();
    let bytes = doc.save();
    let mut doc2 = automerge::AutoCommit::load(black_box(&bytes)).unwrap();
    let n = doc2.get_changes(&[]).len();
    let _ = doc2.save();
    n
}

#[library_benchmark]
fn core_ed25519_signature_verify() -> bool {
    let (secret, public) = tirbase_core::identity::keypair::generate_keypair().unwrap();
    let payload = b"tirbase-core-iai";
    let sig = tirbase_core::identity::keypair::sign(&secret, payload).unwrap();
    tirbase_core::identity::keypair::verify(&public, black_box(payload), &sig).is_ok()
}

library_benchmark_group!(
    name = core_iai_group;
    benchmarks = delta_apply_save_load, core_ed25519_signature_verify
);
main!(library_benchmark_groups = core_iai_group);
