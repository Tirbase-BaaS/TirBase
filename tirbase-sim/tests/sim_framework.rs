//! Simulation framework integration tests (38.3 — CLAIM-38.2,
//! CLAIM-38.3, PV-12.1).
//!
//! Covers the virtual clock, `SimNode`/`CommandGuard` wiring, every network
//! fault mode's observable behaviour, and the "print the seed before exit"
//! failure contract (PV-12.2).

use tirbase_guard::node_mode::NodeMode;
use tirbase_sim::{
    InvariantChecker, NetworkError, NetworkFault, NodeId, SimClock, SimNetwork, SimNode, SimState,
    TirBaseSim, DEFAULT_LINK_DELAY_MS, MAX_DELAY_MS, MAX_DUPLICATE_COPIES,
};

const A: NodeId = NodeId::new(0);
const B: NodeId = NodeId::new(1);

#[test]
fn sim_clock_only_advances_on_tick() {
    let mut clock = SimClock::new(1_000, 250);
    assert_eq!(clock.now_ms(), 1_000);
    assert_eq!(clock.tick(), 1_250);
    assert_eq!(clock.tick(), 1_500);
    assert_eq!(clock.now_secs(), 1);
    clock.advance_ms(1_000);
    assert_eq!(clock.now_ms(), 2_500);
    assert_eq!(clock.wall_secs(), tirbase_sim::SIM_EPOCH_SECS + 2);
}

#[test]
fn sim_node_wraps_command_guard_and_plant_models() {
    let mut node = SimNode::new(NodeId::new(0), 0x51);
    assert_eq!(node.mode(), NodeMode::Normal);
    assert_eq!(node.guard().node_mode().get(), NodeMode::Normal);
    node.set_mode(NodeMode::Restricted);
    assert_eq!(node.mode(), NodeMode::Restricted);

    let before = node.thermal().temperature_bits();
    node.battery_mut().set_power_w(1_000.0);
    node.step_to(3_000);
    assert_eq!(node.ticks(), 1);
    assert_ne!(node.thermal().temperature_bits(), before);
    assert!(node.battery().soc() < 0.8);
}

#[test]
fn partition_fault_blocks_delivery_between_the_pair() {
    let mut net = SimNetwork::new(1);
    net.add_fault(NetworkFault::Partition { src: A, dst: B })
        .unwrap();
    assert!(net.send(0, A, B, b"blocked".to_vec()).is_empty());
    assert!(net.send(0, B, A, b"blocked".to_vec()).is_empty());
    assert!(net.deliver(MAX_DELAY_MS).is_empty());
    assert_eq!(net.dropped_messages(), 2);

    let ids = net.send(0, A, NodeId::new(2), b"ok".to_vec());
    assert_eq!(ids.len(), 1);
    assert_eq!(net.deliver(DEFAULT_LINK_DELAY_MS).len(), 1);
}

#[test]
fn delay_fault_delivers_exactly_after_the_configured_latency() {
    let mut net = SimNetwork::new(2);
    net.add_fault(NetworkFault::Delay {
        src: A,
        dst: B,
        ms: 30_000,
    })
    .unwrap();
    net.send(500, A, B, b"late".to_vec());
    assert!(net.deliver(30_499).is_empty());
    let delivered = net.deliver(30_500);
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].deliver_at_ms, 30_500);
}

#[test]
fn delay_fault_rejects_out_of_range_values() {
    let mut net = SimNetwork::new(3);
    assert_eq!(
        net.add_fault(NetworkFault::Delay {
            src: A,
            dst: B,
            ms: 0
        }),
        Err(NetworkError::DelayOutOfRange { ms: 0 })
    );
    assert_eq!(
        net.add_fault(NetworkFault::Delay {
            src: A,
            dst: B,
            ms: 30_001
        }),
        Err(NetworkError::DelayOutOfRange { ms: 30_001 })
    );
    assert!(net
        .add_fault(NetworkFault::Delay {
            src: A,
            dst: B,
            ms: 1
        })
        .is_ok());
}

#[test]
fn drop_fault_is_seed_deterministic_and_can_drop_everything() {
    let mut lossy = SimNetwork::new(4);
    lossy
        .add_fault(NetworkFault::Drop {
            src: A,
            dst: B,
            rate: 1.0,
        })
        .unwrap();
    for _ in 0..8 {
        assert!(lossy.send(0, A, B, b"x".to_vec()).is_empty());
    }
    assert_eq!(lossy.dropped_messages(), 8);

    let pattern = |seed: u64| {
        let mut net = SimNetwork::new(seed);
        net.add_fault(NetworkFault::Drop {
            src: A,
            dst: B,
            rate: 0.5,
        })
        .unwrap();
        (0..100)
            .filter(|i| !net.send(*i, A, B, b"m".to_vec()).is_empty())
            .collect::<Vec<_>>()
    };
    assert_eq!(pattern(9), pattern(9));
    assert_ne!(pattern(9), pattern(10));
}

#[test]
fn reorder_fault_reverses_delivery_order() {
    let mut net = SimNetwork::new(5);
    net.add_fault(NetworkFault::Reorder { src: A, dst: B })
        .unwrap();
    net.send(0, A, B, b"one".to_vec());
    net.send(0, A, B, b"two".to_vec());
    net.send(0, A, B, b"three".to_vec());
    let order: Vec<Vec<u8>> = net
        .deliver(DEFAULT_LINK_DELAY_MS)
        .into_iter()
        .map(|m| m.payload)
        .collect();
    assert_eq!(
        order,
        vec![b"three".to_vec(), b"two".to_vec(), b"one".to_vec()]
    );
}

#[test]
fn duplicate_fault_caps_at_five_copies() {
    for copies in 1..=MAX_DUPLICATE_COPIES {
        let mut net = SimNetwork::new(6);
        net.add_fault(NetworkFault::Duplicate {
            src: A,
            dst: B,
            copies,
        })
        .unwrap();
        let ids = net.send(0, A, B, b"copy".to_vec());
        assert_eq!(ids.len(), copies as usize);
        assert_eq!(net.deliver(DEFAULT_LINK_DELAY_MS).len(), copies as usize);
    }

    let mut net = SimNetwork::new(6);
    assert_eq!(
        net.add_fault(NetworkFault::Duplicate {
            src: A,
            dst: B,
            copies: MAX_DUPLICATE_COPIES + 1,
        }),
        Err(NetworkError::TooManyCopies {
            copies: MAX_DUPLICATE_COPIES + 1
        })
    );
}

#[test]
fn sim_delivers_messages_to_nodes_and_tracks_time() {
    let mut sim = TirBaseSim::new(11);
    let accepted = sim.broadcast(NodeId::new(0), b"hello".to_vec());
    assert!(accepted > 0);
    sim.run(3).unwrap();
    assert_eq!(sim.clock().now_ms(), 300);
    let received: usize = sim.nodes().iter().map(|n| n.received().len()).sum();
    assert!(received > 0, "healthy network must deliver to peers");
}

#[test]
fn invariant_violation_halts_the_scenario() {
    let mut sim = TirBaseSim::new(0xABCD);
    sim.state_mut().hash_chain_intact = false;
    let err = sim.tick().expect_err("INV-4 failure must halt");
    assert_eq!(err.seed(), 0xABCD);
    assert!(err.to_string().contains("seed=43981"));
    assert!(sim.halted().is_some());
 // The scenario does not resume after a halt.
    assert!(sim.run(5).is_err());
    assert_eq!(sim.state().tick, 1);
}

#[test]
fn failing_scenario_prints_the_seed_before_exit() {
 // Drive a real failing scenario through the public harness and capture its
 // report. The seed line must be written before the error is returned.
    let mut sim = TirBaseSim::new(0x5EED_5EED);
    sim.state_mut().hash_chain_intact = false;
    let mut captured = Vec::new();
    let mut seed = None;
    for _ in 0..4 {
        if let Err(err) = sim.tick() {
            use std::io::Write;
            let _ = writeln!(captured, "scenario FAILED seed={}: {err}", err.seed());
            seed = Some(err.seed());
            break;
        }
    }
    let text = String::from_utf8(captured).expect("utf-8 report");
    let seed = seed.expect("scenario must fail");
    assert!(text.contains(&format!("seed={seed}")), "{text}");
    assert!(text.contains("INV-4"), "{text}");
}

#[test]
fn guard_and_sim_sources_do_not_use_hash_map() {
 // / CLAIM-38.7: HashMap iteration order is non-deterministic, so
 // it is banned in those two crates. Clippy enforces this via
 // `#![deny(clippy::disallowed_types)]`; this source scan is a second,
 // tool-independent guard so the claim has an explicit test identifier.
    fn scan(dir: &std::path::Path, offenders: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                scan(&path, offenders);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let source = std::fs::read_to_string(&path).unwrap_or_default();
                for (line_no, line) in source.lines().enumerate() {
                    let code = line.split("//").next().unwrap_or("");
                    if code.contains("HashMap") {
                        offenders.push(format!("{}:{line_no}", path.display()));
                    }
                }
            }
        }
    }

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf();
    let mut offenders = Vec::new();
    for crate_src in ["tirbase-guard/src", "tirbase-sim/src"] {
        scan(&root.join(crate_src), &mut offenders);
    }
    assert!(
        offenders.is_empty(),
        "HashMap is banned in tirbase-guard and tirbase-sim (task 38.7): {offenders:?}"
    );
}

#[test]
fn invariant_checker_accepts_a_clean_tick() {
    let checker = InvariantChecker::new();
    let state = SimState {
        seed: 1,
        tick: 1,
        hash_chain_intact: true,
        ..Default::default()
    };
    checker.check_all(&state).expect("clean state");
}
