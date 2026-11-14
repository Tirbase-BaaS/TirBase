// SPDX-License-Identifier: AGPL-3.0-only

//! Core throughput/latency benchmarks (CLAIM-40.3, PV-15.3).
//! Delta apply throughput is benchmarked via Automerge apply path; iai-callgrind
//! provides instruction-count gating on CI.

use automerge::transaction::Transactable;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, Criterion};

fn bench_delta_apply_throughput(c: &mut Criterion) {
    c.bench_function("delta_apply_automerge_save_load", |b| {
        b.iter_batched(
            || {
                let mut doc = automerge::AutoCommit::new();
                doc.put(automerge::ROOT, "k", "v").unwrap();
                doc.save()
            },
            |bytes| {
                let mut doc = automerge::AutoCommit::load(black_box(&bytes)).unwrap();
                let changes = doc.get_changes(&[]);
                let _ = doc.save();
                black_box(changes.len())
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_signature_verify_path(c: &mut Criterion) {
    let (secret, public) = tirbase_core::identity::keypair::generate_keypair().unwrap();
    let payload = b"tirbase-core-bench";
    let sig = tirbase_core::identity::keypair::sign(&secret, payload).unwrap();
    c.bench_function("core_ed25519_signature_verify", |b| {
        b.iter(|| {
            let r = tirbase_core::identity::keypair::verify(&public, black_box(payload), &sig);
            black_box(r.is_ok())
        })
    });
}

criterion_group!(
    core_benches,
    bench_delta_apply_throughput,
    bench_signature_verify_path
);
criterion_main!(core_benches);
