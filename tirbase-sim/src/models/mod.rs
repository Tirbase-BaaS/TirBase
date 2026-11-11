//! Deterministic physical models for the simulator (tasks 38.4/38.5 —
//! CLAIM-38.4/CLAIM-38.5, PV-12.3).
//!
//! Both models use the `libm` crate for every non-linear function. `libm` is a
//! pure-Rust implementation, so identical seeds produce bit-identical
//! trajectories on every target. The platform `std` float methods delegate to
//! the system math library and are permitted to differ in the last bit between
//! x86_64 and ARM (or even between glibc versions), so they must not be used.

pub mod battery;
pub mod thermal;

pub use battery::BatteryModel;
pub use thermal::ThermalModel;

#[cfg(test)]
mod tests {
    /// Patterns that indicate a platform libm call (`std`'s `f64` methods)
    /// instead of the deterministic `libm` crate (PV-12.3 wiring mutation check:
    /// swapping `libm::exp` for `f64::exp` must fail this test).
    const STD_FLOAT_PATTERNS: &[&str] = &[
        "f64::exp",
        "f64::sqrt",
        "f64::powf",
        "f64::ln",
        ".exp(",
        ".sqrt(",
        ".powf(",
        ".ln(",
        ".sin(",
        ".cos(",
    ];

    fn assert_uses_libm_only(source_name: &str, source: &str) {
        for pattern in STD_FLOAT_PATTERNS {
            assert!(
                !source.contains(pattern),
                "{source_name} uses platform float math `{pattern}`; use `libm` instead \
                 (PV-12.3 bit-identical determinism)"
            );
        }
        assert!(
            source.contains("libm::"),
            "{source_name} must call `libm` for deterministic floating-point math"
        );
    }

    #[test]
    fn thermal_and_battery_models_use_libm_not_std_float_math() {
        assert_uses_libm_only("models/thermal.rs", include_str!("thermal.rs"));
        assert_uses_libm_only("models/battery.rs", include_str!("battery.rs"));
    }
}
