//! CLAIM-34.3: canonical cold-room thermal model is bit-identical across crates.

use tirbase_drivers::cold_room_sim::FirstOrderThermalModel;
use tirbase_sim::drivers::cold_room::ColdRoomThermalSim;

#[test]
fn claim_34_3_canonical_thermal_model_bit_identical_across_crates() {
    let seeds = [0u64, 1, 42, 0xC01D, 0xDEAD_BEEF, u64::MAX / 3];
    for seed in seeds {
        let mut a = FirstOrderThermalModel::new(seed, 8_000, 22_000);
        let mut b = ColdRoomThermalSim::new(seed);
        let mut a_traj = Vec::with_capacity(512);
        let mut b_traj = Vec::with_capacity(512);
        for _ in 0..512 {
            a_traj.push(a.step());
            b_traj.push(b.step());
        }
        assert_eq!(
            a_traj, b_traj,
            "thermal trajectories diverged for seed={seed}"
        );
    }

    // ColdRoomSimDriver uses the same canonical model.
    let mut drv = tirbase_drivers::ColdRoomSimDriver::new(0xC01D, "cold_room#1");
    let mut sim = ColdRoomThermalSim::new(0xC01D);
    for step in 0..256 {
        assert_eq!(
            drv.model.step(),
            sim.step(),
            "driver wrapper diverged at step={step}"
        );
    }
}
