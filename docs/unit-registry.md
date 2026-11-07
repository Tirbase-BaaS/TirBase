# Unit Registry

<!-- CLAIM-3.10 -->

## Purpose

TirBase represents all guard-facing physical values as `FixedPointValue { mantissa: i64, exponent: i8, unit_id: UnitId }` (PV-21.1). The `UnitId` field is a **project-maintained integer**, not a free string. Using integers instead of strings eliminates:

- Unit ambiguity bypass paths (e.g., `"°C"` vs `"degC"` vs `"celsius"`)
- String-comparison bugs at the guard boundary
- Per-comparison heap allocation in hot paths

`UnitId` values are encoded in the compact binary representation of `FixedPointValue` and therefore must be stable across versions. This file is the **authoritative source** of all valid `UnitId` values. Drivers and the guard MUST use these integer IDs — never raw strings.

---

## Reserved ID

`UnitId(0)` is reserved as **unknown / dimensionless** and **SHALL NOT** be used for physical quantities. Any command whose unit_id is 0 for a typed parameter MUST be rejected by the guard at Stage 10.

---

## Cross-Unit Arithmetic Policy

Cross-unit arithmetic is **forbidden** in the guard (PV-21.1). When the guard evaluates a command, it checks that the token's `unit_id` exactly matches the `unit_id` declared in the device model's `ParameterSpec` for that parameter. Commands whose unit does not match are rejected with `UnitMismatchError`. No implicit conversion is performed.

---

## Registry Table

| Unit ID (integer) | Symbol | Label | Dimension | SI Base | Notes |
|---|---|---|---|---|---|
| 1 | degC | Degrees Celsius | Temperature | K | Offset: T(K) = T(°C) + 273.15 |
| 2 | Pa | Pascal | Pressure | kg·m⁻¹·s⁻² | 1 Pa = 1 N/m² |
| 3 | rpm | Revolutions per minute | Angular velocity | rad·s⁻¹ | 1 rpm = 2π/60 rad/s |
| 4 | bar | Bar | Pressure | kg·m⁻¹·s⁻² | 1 bar = 100 000 Pa |
| 5 | kW | Kilowatt | Power | kg·m²·s⁻³ | 1 kW = 1000 W |
| 6 | percent | Percent | Dimensionless ratio | — | Range typically [0, 100] |
| 7 | boolean | Boolean | Dimensionless | — | 0 = false, 1 = true; mantissa MUST be 0 or 1 |
| 8 | kPa | Kilopascal | Pressure | kg·m⁻¹·s⁻² | 1 kPa = 1000 Pa |
| 9 | m3h | Cubic metres per hour | Volumetric flow rate | m³·s⁻¹ | 1 m³/h = 1/3600 m³/s |
| 10 | V | Volt | Electric potential | kg·m²·A⁻¹·s⁻³ | |
| 11 | A | Ampere | Electric current | A | SI base unit |
| 12 | Hz | Hertz | Frequency | s⁻¹ | |

---

## Append-Only Rule

Unit IDs are **append-only**:

- **Never reuse or renumber an ID.** Changing what an integer means breaks binary compatibility with stored data and in-flight tokens.
- **Never delete a row.** If a unit becomes deprecated, add a `Deprecated` note in the Notes column and update the constant in `tirbase-types`, but keep the row and the ID.
- The next unit to be added receives the next sequential integer (currently: **13**).

---

## How to Add a New Unit

1. Append a new row to the Registry Table above with the next available integer ID.
2. Add the corresponding `pub const UNIT_<SYMBOL>: UnitId = UnitId(<id>);` constant to `tirbase-types/src/unit_id.rs` (or the canonical location for `UnitId` constants in `tirbase-types`).
3. Update `UnitDescriptor` entries in `tirbase-types` if a static descriptor table is maintained.
4. Open a PR that includes both this file and the `tirbase-types` change so the registry and the code stay in sync.
5. Do **not** assign ID 0 to any new unit — it remains reserved.

---

## Changelog

| Version | Change | Requirement |
|---|---|---|
| initial | IDs 1–12 defined: degC, Pa, rpm, bar, kW, percent, boolean, kPa, m3h, V, A, Hz | PV-21.1 |
