// SPDX-License-Identifier: Apache-2.0

//! Offline POS scenario pack (POS-09), data only.
//!
//! The POS scenario pack describes payment, split, pricing and kitchen-display
//! conflicts as data: an initial state, a partition timeline, commands,
//! approvals, expected permit decisions, expected ledger rows and a named
//! invariant. This module only parses and structurally validates that data. It
//! contains no POS runtime and never executes a scenario; the AGPL gateway
//! integration test does that against `tirbase-pos`.

use super::{safe_pack_path, PackError};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

/// Manifest file at the root of a POS scenario pack.
pub const POS_PACK_MANIFEST_FILE: &str = "pack.toml";
/// Schema version understood by this loader.
pub const POS_PACK_SCHEMA_VERSION: u32 = 1;
/// Every POS scenario pack is published under this licence.
pub const POS_PACK_LICENCE: &str = "Apache-2.0";
/// Manifest `kind` required for a POS scenario pack.
pub const POS_PACK_KIND: &str = "pos_offline";
/// The only executable entry a pack may contain.
pub const POS_PACK_LAUNCHER: &str = "run.sh";

/// The six scenarios the POS-09 pack must cover.
pub const POS_PACK_REQUIRED_SCENARIOS: &[&str] = &[
    "double_charge_on_reconnect",
    "replayed_refund",
    "split_bill_conflict",
    "offline_price_change",
    "void_after_capture",
    "duplicate_kds_ticket",
];

/// Permit decisions a command may expect.
pub const POS_COMMAND_PERMITS: &[&str] = &[
    "accepted",
    "replayed",
    "denied",
    "winner",
    "loser",
    "deduplicated",
];

/// A parsed POS scenario pack manifest.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PosPackManifest {
    /// Must equal [`POS_PACK_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Pack identity; must match the pack directory name.
    pub id: String,
    /// Pack version (`major.minor.patch`).
    pub version: String,
    /// Human-readable title.
    pub title: String,
    /// One-paragraph description.
    pub description: String,
    /// SPDX licence. Must be [`POS_PACK_LICENCE`].
    pub licence: String,
    /// Must be [`POS_PACK_KIND`].
    pub kind: String,
    /// Minimum TirBase release the pack is validated against.
    pub tirbase_min_version: String,
    /// The launcher. Must be [`POS_PACK_LAUNCHER`].
    pub run: String,
    /// Documentation files relative to the pack root.
    pub docs: Vec<String>,
    /// Expected-output document relative to the pack root.
    pub expected: String,
    /// Scenario documents relative to the pack root.
    pub scenarios: Vec<String>,
}

/// One declared partition interval.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PosPartition {
    /// Terminal or actor that is partitioned.
    pub actor: String,
    /// Whether the actor is cut off from the rest of the estate.
    pub offline: bool,
    /// Start of the interval, in caller-supplied milliseconds.
    pub from_ms: i64,
    /// End of the interval, in caller-supplied milliseconds.
    pub to_ms: i64,
    /// Why the partition happened.
    pub reason: String,
}

/// The initial POS state a scenario starts from.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PosInitial {
    /// ISO 4217 currency code.
    pub currency: String,
    /// Terminal that owns the check.
    pub terminal: String,
    /// Operator presenting the commands.
    pub operator: String,
    /// Registered approver.
    pub approver: String,
    /// Active terminal epoch.
    pub epoch: u64,
    /// Check identifier.
    pub check: String,
    /// Check total in minor units.
    pub check_total_minor: i64,
    /// Tip in minor units.
    pub tip_minor: i64,
    /// `open` or `closed`.
    pub check_status: String,
    /// Payment intent identifier.
    pub intent: String,
    /// `authorized` or `captured`.
    pub intent_status: String,
    /// Payment identifier.
    pub payment: String,
    /// Pricing state, for the offline-price-change scenario.
    #[serde(default)]
    pub pricing: Option<PosPricing>,
    /// Split state, for the split-bill-conflict scenario.
    #[serde(default)]
    pub split: Option<PosSplit>,
    /// Kitchen-display state, for the duplicate-KDS-ticket scenario.
    #[serde(default)]
    pub kds: Option<PosKds>,
}

/// Catalog and price versions used by the offline-price-change scenario.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PosPricing {
    /// Catalog item identifier.
    pub item: String,
    /// Item display name.
    pub item_name: String,
    /// Price before the offline change, in minor units.
    pub old_price_minor: i64,
    /// Price after the offline change, in minor units.
    pub new_price_minor: i64,
    /// When the new price version becomes effective, in milliseconds.
    pub new_effective_ms: i64,
    /// Tax rate in parts per million.
    pub tax_rate_ppm: i32,
    /// Identifier of the old price-book version.
    pub old_version: String,
    /// Identifier of the new price-book version.
    pub new_version: String,
}

/// Check and line split by the split-bill-conflict scenario.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PosSplit {
    /// Source check being split.
    pub source_check: String,
    /// Line item moved by each competing split.
    pub line_item: String,
    /// Target identifier chosen by the winning terminal.
    pub target_a: String,
    /// Target identifier chosen by the losing terminal.
    pub target_b: String,
    /// Lamport clock shared by the competing operations.
    pub lamport: u64,
}

/// Ticket issued to the kitchen display.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PosKds {
    /// Ticket identifier.
    pub ticket: String,
    /// Ticket sequence number.
    pub sequence: u64,
    /// Order the ticket belongs to.
    pub order: String,
    /// Check the ticket belongs to.
    pub check: String,
    /// Station for the single line.
    pub station: String,
    /// Line identifier.
    pub line: String,
    /// Line display name.
    pub name: String,
    /// Line quantity in thousandths.
    pub quantity_thousandths: i64,
}

/// One command in a scenario.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PosCommand {
    /// Unique command identifier within the scenario.
    pub id: String,
    /// Command kind: `capture`, `refund`, `void`, `split_check`,
    /// `publish_price`, `close_check` or `kds_submit`.
    pub kind: String,
    /// Actor issuing the command.
    pub actor: String,
    /// Caller-supplied command time in milliseconds.
    pub at_ms: i64,
    /// Expected permit decision.
    pub expect: String,
    /// Stable denial code, required when `expect = "denied"`.
    #[serde(default)]
    pub denial: Option<String>,
    /// Payment nonce for payment commands.
    #[serde(default)]
    pub nonce: Option<String>,
    /// Monotonic counter for payment commands.
    #[serde(default)]
    pub counter: Option<u64>,
    /// Amount in minor units, or the new price for `publish_price`.
    #[serde(default)]
    pub amount_minor: Option<i64>,
    /// Approval identifier bound to a payment command.
    #[serde(default)]
    pub approval: Option<String>,
    /// Target check for `split_check`.
    #[serde(default)]
    pub target_check: Option<String>,
    /// Line item for `split_check`.
    #[serde(default)]
    pub line_item: Option<String>,
    /// Lamport clock for `split_check`.
    #[serde(default)]
    pub lamport: Option<u64>,
    /// Effective time for `publish_price`.
    #[serde(default)]
    pub effective_ms: Option<i64>,
}

/// One approval declared by a scenario.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PosApproval {
    /// Approval identifier.
    pub id: String,
    /// `refund` or `void_payment`.
    pub action: String,
    /// Amount in minor units.
    pub amount_minor: i64,
    /// Reason bound into the approval.
    pub reason: String,
    /// Operator requesting the approval.
    pub requester: String,
    /// Operator signing the approval.
    pub approver: String,
    /// Request time in milliseconds.
    pub requested_at_ms: i64,
    /// Expiry in milliseconds.
    pub expires_at_ms: i64,
}

/// One scenario document.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PosScenario {
    /// Must equal [`POS_PACK_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Unique scenario id.
    pub id: String,
    /// Human-readable title.
    pub title: String,
    /// The attempted abuse.
    pub attack: String,
    /// Named invariant the defended run must satisfy.
    pub invariant: String,
    /// Initial state.
    pub initial: PosInitial,
    /// Partition intervals.
    pub partitions: Vec<PosPartition>,
    /// Ordered commands.
    pub commands: Vec<PosCommand>,
    /// Approvals declared before the commands run.
    pub approvals: Vec<PosApproval>,
}

/// Expected permit decisions and ledger rows for one scenario.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PosExpectedScenario {
    /// Scenario id.
    pub id: String,
    /// One permit per command, in command order.
    pub permit: Vec<String>,
    /// Canonical `key=value` ledger rows in sorted order.
    pub ledger: Vec<String>,
}

/// The expected-output document.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PosExpectedOutputs {
    /// Must equal [`POS_PACK_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// One row per scenario.
    pub scenario: Vec<PosExpectedScenario>,
}

/// A loaded and structurally validated POS scenario pack.
#[derive(Debug, Clone)]
pub struct PosPack {
    /// Pack root.
    pub root: PathBuf,
    /// Parsed manifest.
    pub manifest: PosPackManifest,
    /// Parsed scenarios.
    pub scenarios: Vec<PosScenario>,
    /// Parsed expected outcomes.
    pub expected: PosExpectedOutputs,
}

impl PosPack {
    /// One scenario by id.
    pub fn scenario(&self, id: &str) -> Option<&PosScenario> {
        self.scenarios.iter().find(|scenario| scenario.id == id)
    }

    /// Expected outcome by scenario id.
    pub fn outcome(&self, id: &str) -> Option<&PosExpectedScenario> {
        self.expected
            .scenario
            .iter()
            .find(|outcome| outcome.id == id)
    }
}

fn validation(message: impl Into<String>) -> PackError {
    PackError::Validation(message.into())
}

fn read_document(root: &Path, relative: &str) -> Result<String, PackError> {
    let path = safe_pack_path(root, relative)?;
    std::fs::read_to_string(&path).map_err(|error| PackError::Io {
        path: relative.to_string(),
        error,
    })
}

fn parse_toml<T: serde::de::DeserializeOwned>(relative: &str, text: &str) -> Result<T, PackError> {
    toml::from_str(text).map_err(|error| PackError::Toml {
        path: relative.to_string(),
        error,
    })
}

/// Load and structurally validate a POS scenario pack from `root`.
pub fn load_pos_pack(root: impl AsRef<Path>) -> Result<PosPack, PackError> {
    let root = root.as_ref();
    let manifest_text = read_document(root, POS_PACK_MANIFEST_FILE)?;
    let manifest: PosPackManifest = parse_toml(POS_PACK_MANIFEST_FILE, &manifest_text)?;
    validate_manifest(root, &manifest)?;

    let mut scenarios = Vec::with_capacity(manifest.scenarios.len());
    for relative in &manifest.scenarios {
        let text = read_document(root, relative)?;
        let scenario: PosScenario = parse_toml(relative, &text)?;
        validate_scenario(relative, &scenario)?;
        scenarios.push(scenario);
    }
    if scenarios.is_empty() {
        return Err(validation("POS pack declares no scenarios"));
    }
    let ids: BTreeSet<&str> = scenarios
        .iter()
        .map(|scenario| scenario.id.as_str())
        .collect();
    if ids.len() != scenarios.len() {
        return Err(validation("POS pack lists a scenario id more than once"));
    }
    for required in POS_PACK_REQUIRED_SCENARIOS {
        if !ids.contains(required) {
            return Err(validation(format!(
                "POS pack must declare required scenario '{required}'"
            )));
        }
    }

    let expected_text = read_document(root, &manifest.expected)?;
    let expected: PosExpectedOutputs = parse_toml(&manifest.expected, &expected_text)?;
    validate_expected(&scenarios, &expected)?;

    for relative in manifest
        .docs
        .iter()
        .chain(std::iter::once(&manifest.expected))
        .chain(std::iter::once(&manifest.run))
        .chain(manifest.scenarios.iter())
    {
        let _ = safe_pack_path(root, relative)?;
    }

    Ok(PosPack {
        root: root.to_path_buf(),
        manifest,
        scenarios,
        expected,
    })
}

fn validate_manifest(root: &Path, manifest: &PosPackManifest) -> Result<(), PackError> {
    if manifest.schema_version != POS_PACK_SCHEMA_VERSION {
        return Err(validation(format!(
            "unsupported POS pack schema_version {}; this loader reads {}",
            manifest.schema_version, POS_PACK_SCHEMA_VERSION
        )));
    }
    let directory = root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| validation("POS pack directory has no usable name"))?;
    if manifest.id != directory {
        return Err(validation(format!(
            "manifest id '{}' must match the pack directory '{directory}'",
            manifest.id
        )));
    }
    for (field, value) in [
        ("id", &manifest.id),
        ("title", &manifest.title),
        ("description", &manifest.description),
        ("kind", &manifest.kind),
        ("tirbase_min_version", &manifest.tirbase_min_version),
    ] {
        if value.trim().is_empty() {
            return Err(validation(format!(
                "manifest field '{field}' must not be empty"
            )));
        }
    }
    if manifest.licence != POS_PACK_LICENCE {
        return Err(validation(format!(
            "pack licence must be '{POS_PACK_LICENCE}', found '{}'",
            manifest.licence
        )));
    }
    if manifest.kind != POS_PACK_KIND {
        return Err(validation(format!(
            "pack kind must be '{POS_PACK_KIND}', found '{}'",
            manifest.kind
        )));
    }
    if manifest.run != POS_PACK_LAUNCHER {
        return Err(validation(format!(
            "manifest run must be '{POS_PACK_LAUNCHER}'"
        )));
    }
    validate_version(&manifest.version)?;
    validate_version(&manifest.tirbase_min_version)?;
    if manifest.docs.is_empty() {
        return Err(validation("manifest must declare pack documentation"));
    }
    if manifest.scenarios.is_empty() {
        return Err(validation("manifest must declare scenarios"));
    }
    Ok(())
}

fn validate_version(version: &str) -> Result<(), PackError> {
    let parts: Vec<&str> = version.split('.').collect();
    if parts.len() != 3
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(validation(format!(
            "version '{version}' must be a numeric major.minor.patch"
        )));
    }
    Ok(())
}

fn validate_scenario(relative: &str, scenario: &PosScenario) -> Result<(), PackError> {
    if scenario.schema_version != POS_PACK_SCHEMA_VERSION {
        return Err(validation(format!(
            "scenario '{relative}' schema_version must be {POS_PACK_SCHEMA_VERSION}"
        )));
    }
    if scenario.id.trim().is_empty() {
        return Err(validation(format!("scenario '{relative}' has an empty id")));
    }
    if scenario.title.trim().is_empty() || scenario.attack.trim().is_empty() {
        return Err(validation(format!(
            "scenario '{}' must describe its title and attack",
            scenario.id
        )));
    }
    if scenario.invariant.trim().is_empty() {
        return Err(validation(format!(
            "scenario '{}' must declare an invariant",
            scenario.id
        )));
    }
    validate_initial(&scenario.id, &scenario.initial)?;
    validate_partitions(&scenario.id, &scenario.partitions)?;
    validate_commands(&scenario.id, &scenario.initial, &scenario.commands)?;
    validate_approvals(&scenario.id, &scenario.initial, &scenario.approvals)?;
    validate_approval_references(&scenario.id, &scenario.commands, &scenario.approvals)?;
    validate_scenario_specific(&scenario.id, &scenario.initial, &scenario.commands)?;
    Ok(())
}

fn validate_initial(id: &str, initial: &PosInitial) -> Result<(), PackError> {
    for (field, value) in [
        ("currency", &initial.currency),
        ("terminal", &initial.terminal),
        ("operator", &initial.operator),
        ("approver", &initial.approver),
        ("check", &initial.check),
        ("intent", &initial.intent),
        ("intent_status", &initial.intent_status),
        ("payment", &initial.payment),
    ] {
        if value.trim().is_empty() {
            return Err(validation(format!(
                "scenario '{id}' initial.{field} must not be empty"
            )));
        }
    }
    if initial.currency.len() != 3
        || !initial
            .currency
            .bytes()
            .all(|byte| byte.is_ascii_uppercase())
    {
        return Err(validation(format!(
            "scenario '{id}' initial.currency must be three uppercase ASCII letters"
        )));
    }
    if initial.epoch == 0 {
        return Err(validation(format!(
            "scenario '{id}' initial.epoch must be positive"
        )));
    }
    if initial.check_total_minor <= 0 {
        return Err(validation(format!(
            "scenario '{id}' initial.check_total_minor must be positive"
        )));
    }
    if initial.tip_minor < 0 || initial.tip_minor > initial.check_total_minor {
        return Err(validation(format!(
            "scenario '{id}' initial.tip_minor must be between zero and the check total"
        )));
    }
    if !matches!(initial.check_status.as_str(), "open" | "closed") {
        return Err(validation(format!(
            "scenario '{id}' initial.check_status must be 'open' or 'closed'"
        )));
    }
    if !matches!(initial.intent_status.as_str(), "authorized" | "captured") {
        return Err(validation(format!(
            "scenario '{id}' initial.intent_status must be 'authorized' or 'captured'"
        )));
    }
    if let Some(pricing) = &initial.pricing {
        for (field, value) in [
            ("item", &pricing.item),
            ("item_name", &pricing.item_name),
            ("old_version", &pricing.old_version),
            ("new_version", &pricing.new_version),
        ] {
            if value.trim().is_empty() {
                return Err(validation(format!(
                    "scenario '{id}' initial.pricing.{field} must not be empty"
                )));
            }
        }
        if pricing.old_price_minor <= 0 || pricing.new_price_minor <= 0 {
            return Err(validation(format!(
                "scenario '{id}' price-book prices must be positive"
            )));
        }
        if pricing.new_effective_ms <= 0 {
            return Err(validation(format!(
                "scenario '{id}' new price effective time must be positive"
            )));
        }
        if pricing.tax_rate_ppm < 0 || pricing.tax_rate_ppm > 1_000_000 {
            return Err(validation(format!(
                "scenario '{id}' tax rate must be between 0 and 100 percent"
            )));
        }
    }
    if let Some(split) = &initial.split {
        for (field, value) in [
            ("source_check", &split.source_check),
            ("line_item", &split.line_item),
            ("target_a", &split.target_a),
            ("target_b", &split.target_b),
        ] {
            if value.trim().is_empty() {
                return Err(validation(format!(
                    "scenario '{id}' initial.split.{field} must not be empty"
                )));
            }
        }
        if split.target_a == split.target_b {
            return Err(validation(format!(
                "scenario '{id}' split targets must differ"
            )));
        }
        if split.lamport == 0 {
            return Err(validation(format!(
                "scenario '{id}' split lamport must be positive"
            )));
        }
    }
    if let Some(kds) = &initial.kds {
        for (field, value) in [
            ("ticket", &kds.ticket),
            ("order", &kds.order),
            ("check", &kds.check),
            ("station", &kds.station),
            ("line", &kds.line),
            ("name", &kds.name),
        ] {
            if value.trim().is_empty() {
                return Err(validation(format!(
                    "scenario '{id}' initial.kds.{field} must not be empty"
                )));
            }
        }
        if kds.sequence == 0 {
            return Err(validation(format!(
                "scenario '{id}' KDS sequence must be positive"
            )));
        }
        if kds.quantity_thousandths <= 0 {
            return Err(validation(format!(
                "scenario '{id}' KDS quantity must be positive"
            )));
        }
        if !matches!(
            kds.station.as_str(),
            "grill" | "fry" | "cold" | "bar" | "expo"
        ) {
            return Err(validation(format!(
                "scenario '{id}' KDS station '{}' is unknown",
                kds.station
            )));
        }
    }
    Ok(())
}

fn validate_partitions(id: &str, partitions: &[PosPartition]) -> Result<(), PackError> {
    if partitions.is_empty() {
        return Err(validation(format!(
            "scenario '{id}' must declare a partition timeline"
        )));
    }
    let mut by_actor: BTreeMap<&str, Vec<(i64, i64)>> = BTreeMap::new();
    for partition in partitions {
        if partition.actor.trim().is_empty() || partition.reason.trim().is_empty() {
            return Err(validation(format!(
                "scenario '{id}' partitions must name an actor and a reason"
            )));
        }
        if !partition.offline {
            return Err(validation(format!(
                "scenario '{id}' partition for '{}' must be offline",
                partition.actor
            )));
        }
        if partition.from_ms < 0 || partition.to_ms <= partition.from_ms {
            return Err(validation(format!(
                "scenario '{id}' partition for '{}' has an invalid interval",
                partition.actor
            )));
        }
        by_actor
            .entry(partition.actor.as_str())
            .or_default()
            .push((partition.from_ms, partition.to_ms));
    }
    for (actor, intervals) in by_actor {
        let mut sorted = intervals;
        sorted.sort_unstable();
        for pair in sorted.windows(2) {
            if pair[1].0 < pair[0].1 {
                return Err(validation(format!(
                    "scenario '{id}' has overlapping partitions for '{actor}'"
                )));
            }
        }
    }
    Ok(())
}

fn validate_commands(
    id: &str,
    initial: &PosInitial,
    commands: &[PosCommand],
) -> Result<(), PackError> {
    if commands.is_empty() {
        return Err(validation(format!("scenario '{id}' has no commands")));
    }
    let mut ids = BTreeSet::new();
    for (index, command) in commands.iter().enumerate() {
        if command.id.trim().is_empty() {
            return Err(validation(format!(
                "scenario '{id}' command {index} has an empty id"
            )));
        }
        if !ids.insert(command.id.as_str()) {
            return Err(validation(format!(
                "scenario '{id}' reuses command id '{}'",
                command.id
            )));
        }
        if command.actor.trim().is_empty() {
            return Err(validation(format!(
                "scenario '{id}' command '{}' has an empty actor",
                command.id
            )));
        }
        if command.at_ms < 0 {
            return Err(validation(format!(
                "scenario '{id}' command '{}' has a negative time",
                command.id
            )));
        }
        if !POS_COMMAND_PERMITS.contains(&command.expect.as_str()) {
            return Err(validation(format!(
                "scenario '{id}' command '{}' has unknown permit '{}'",
                command.id, command.expect
            )));
        }
        if command.expect == "denied" {
            if command.denial.as_deref().unwrap_or("").trim().is_empty() {
                return Err(validation(format!(
                    "scenario '{id}' denied command '{}' must name a denial code",
                    command.id
                )));
            }
        } else if command.denial.is_some() {
            return Err(validation(format!(
                "scenario '{id}' command '{}' has a denial code but is not denied",
                command.id
            )));
        }
        match command.kind.as_str() {
            "capture" | "refund" | "void" => {
                for (field, present) in [
                    ("nonce", command.nonce.is_some()),
                    ("counter", command.counter.is_some()),
                    ("amount_minor", command.amount_minor.is_some()),
                ] {
                    if !present {
                        return Err(validation(format!(
                            "scenario '{id}' command '{}' is missing {field}",
                            command.id
                        )));
                    }
                }
                if command.counter == Some(0) {
                    return Err(validation(format!(
                        "scenario '{id}' command '{}' counter must be positive",
                        command.id
                    )));
                }
                if command.amount_minor.unwrap_or(0) <= 0 {
                    return Err(validation(format!(
                        "scenario '{id}' command '{}' amount must be positive",
                        command.id
                    )));
                }
                if command.kind == "capture" && command.approval.is_some() {
                    return Err(validation(format!(
                        "scenario '{id}' capture command '{}' cannot consume an approval",
                        command.id
                    )));
                }
            }
            "split_check" => {
                for (field, present) in [
                    ("target_check", command.target_check.is_some()),
                    ("line_item", command.line_item.is_some()),
                    ("lamport", command.lamport.is_some()),
                ] {
                    if !present {
                        return Err(validation(format!(
                            "scenario '{id}' command '{}' is missing {field}",
                            command.id
                        )));
                    }
                }
                if command.lamport == Some(0) {
                    return Err(validation(format!(
                        "scenario '{id}' command '{}' lamport must be positive",
                        command.id
                    )));
                }
                if command.target_check.as_deref() == Some(initial.check.as_str()) {
                    return Err(validation(format!(
                        "scenario '{id}' command '{}' targets the source check",
                        command.id
                    )));
                }
            }
            "publish_price" => {
                if command.amount_minor.unwrap_or(0) <= 0 || command.effective_ms.is_none() {
                    return Err(validation(format!(
                        "scenario '{id}' publish_price command '{}' needs a positive price and effective_ms",
                        command.id
                    )));
                }
            }
            "close_check" | "kds_submit" => {}
            other => {
                return Err(validation(format!(
                    "scenario '{id}' command '{}' has unknown kind '{other}'",
                    command.id
                )));
            }
        }
    }
    Ok(())
}

fn validate_approvals(
    id: &str,
    initial: &PosInitial,
    approvals: &[PosApproval],
) -> Result<(), PackError> {
    let mut ids = BTreeSet::new();
    for approval in approvals {
        if approval.id.trim().is_empty() || !ids.insert(approval.id.as_str()) {
            return Err(validation(format!(
                "scenario '{id}' has a duplicate or empty approval id"
            )));
        }
        if !matches!(approval.action.as_str(), "refund" | "void_payment") {
            return Err(validation(format!(
                "scenario '{id}' approval '{}' has unknown action '{}'",
                approval.id, approval.action
            )));
        }
        if approval.amount_minor <= 0 {
            return Err(validation(format!(
                "scenario '{id}' approval '{}' amount must be positive",
                approval.id
            )));
        }
        if approval.reason.trim().is_empty() {
            return Err(validation(format!(
                "scenario '{id}' approval '{}' needs a reason",
                approval.id
            )));
        }
        if approval.requester.trim().is_empty() || approval.approver.trim().is_empty() {
            return Err(validation(format!(
                "scenario '{id}' approval '{}' must name requester and approver",
                approval.id
            )));
        }
        if approval.requester == approval.approver {
            return Err(validation(format!(
                "scenario '{id}' approval '{}' cannot self-approve",
                approval.id
            )));
        }
        if approval.requested_at_ms < 0 || approval.expires_at_ms <= approval.requested_at_ms {
            return Err(validation(format!(
                "scenario '{id}' approval '{}' has an invalid window",
                approval.id
            )));
        }
        if approval.requester != initial.operator && approval.requester != initial.approver {
            return Err(validation(format!(
                "scenario '{id}' approval '{}' requester is not a declared actor",
                approval.id
            )));
        }
        if approval.approver != initial.approver {
            return Err(validation(format!(
                "scenario '{id}' approval '{}' must be signed by the declared approver",
                approval.id
            )));
        }
    }
    Ok(())
}

fn validate_approval_references(
    id: &str,
    commands: &[PosCommand],
    approvals: &[PosApproval],
) -> Result<(), PackError> {
    let mut used = BTreeSet::new();
    for command in commands {
        let Some(approval_id) = &command.approval else {
            continue;
        };
        let approval = approvals
            .iter()
            .find(|approval| &approval.id == approval_id)
            .ok_or_else(|| {
                validation(format!(
                    "scenario '{id}' command '{}' references unknown approval '{approval_id}'",
                    command.id
                ))
            })?;
        let expected_action = match command.kind.as_str() {
            "refund" => "refund",
            "void" => "void_payment",
            other => {
                return Err(validation(format!(
                    "scenario '{id}' command '{}' of kind '{other}' cannot consume an approval",
                    command.id
                )))
            }
        };
        if approval.action != expected_action {
            return Err(validation(format!(
                "scenario '{id}' command '{}' needs a '{expected_action}' approval but '{}' is '{}'",
                command.id, approval.id, approval.action
            )));
        }
        if command.amount_minor != Some(approval.amount_minor) {
            return Err(validation(format!(
                "scenario '{id}' command '{}' amount must equal approval '{}' amount",
                command.id, approval.id
            )));
        }
        used.insert(approval.id.as_str());
    }
    for approval in approvals {
        if !used.contains(approval.id.as_str()) {
            return Err(validation(format!(
                "scenario '{id}' declares unused approval '{}'",
                approval.id
            )));
        }
    }
    Ok(())
}

fn validate_scenario_specific(
    id: &str,
    initial: &PosInitial,
    commands: &[PosCommand],
) -> Result<(), PackError> {
    let kinds: BTreeSet<&str> = commands
        .iter()
        .map(|command| command.kind.as_str())
        .collect();
    let scenario = POS_PACK_REQUIRED_SCENARIOS
        .iter()
        .copied()
        .find(|required| *required == id);
    match scenario {
        Some("offline_price_change") => {
            if initial.pricing.is_none()
                || !kinds.contains("publish_price")
                || !kinds.contains("close_check")
            {
                return Err(validation(
                    "offline_price_change must declare pricing and publish/close commands",
                ));
            }
        }
        Some("split_bill_conflict") => {
            if initial.split.is_none() || !kinds.contains("split_check") {
                return Err(validation(
                    "split_bill_conflict must declare split state and split commands",
                ));
            }
        }
        Some("duplicate_kds_ticket") => {
            if initial.kds.is_none() || !kinds.contains("kds_submit") {
                return Err(validation(
                    "duplicate_kds_ticket must declare KDS state and submit commands",
                ));
            }
        }
        Some(_) => {
            let payment_kind = match id {
                "replayed_refund" => "refund",
                "void_after_capture" => "void",
                "double_charge_on_reconnect" => "capture",
                _ => "",
            };
            if !payment_kind.is_empty() && !kinds.contains(payment_kind) {
                return Err(validation(format!(
                    "scenario '{id}' must declare a {payment_kind} command"
                )));
            }
        }
        None => {}
    }
    Ok(())
}

fn validate_expected(
    scenarios: &[PosScenario],
    expected: &PosExpectedOutputs,
) -> Result<(), PackError> {
    if expected.schema_version != POS_PACK_SCHEMA_VERSION {
        return Err(validation(format!(
            "expected-output schema_version must be {POS_PACK_SCHEMA_VERSION}"
        )));
    }
    let scenario_ids: BTreeSet<&str> = scenarios
        .iter()
        .map(|scenario| scenario.id.as_str())
        .collect();
    let expected_ids: BTreeSet<&str> = expected
        .scenario
        .iter()
        .map(|outcome| outcome.id.as_str())
        .collect();
    if expected_ids.len() != expected.scenario.len() {
        return Err(validation(
            "expected-output document lists a scenario more than once",
        ));
    }
    if scenario_ids != expected_ids {
        return Err(validation(
            "expected outputs must cover every scenario exactly once",
        ));
    }
    for scenario in scenarios {
        let outcome = expected
            .scenario
            .iter()
            .find(|outcome| outcome.id == scenario.id)
            .expect("coverage checked above");
        let permits: Vec<&str> = scenario
            .commands
            .iter()
            .map(|command| command.expect.as_str())
            .collect();
        let expected_permits: Vec<&str> = outcome.permit.iter().map(String::as_str).collect();
        if permits != expected_permits {
            return Err(validation(format!(
                "expected permits for '{}' do not match its commands",
                scenario.id
            )));
        }
        if outcome.ledger.is_empty() {
            return Err(validation(format!(
                "expected output for '{}' must declare ledger rows",
                scenario.id
            )));
        }
        let mut keys = BTreeSet::new();
        for row in &outcome.ledger {
            let Some((key, value)) = row.split_once('=') else {
                return Err(validation(format!(
                    "expected ledger row '{row}' in '{}' must be key=value",
                    scenario.id
                )));
            };
            if key.trim().is_empty() || value.trim().is_empty() {
                return Err(validation(format!(
                    "expected ledger row '{row}' in '{}' has an empty key or value",
                    scenario.id
                )));
            }
            if !keys.insert(key) {
                return Err(validation(format!(
                    "expected output for '{}' repeats ledger key '{key}'",
                    scenario.id
                )));
            }
        }
        let sorted: Vec<&str> = outcome.ledger.iter().map(String::as_str).collect();
        let mut sorted_owned = sorted.clone();
        sorted_owned.sort_unstable();
        if sorted != sorted_owned {
            return Err(validation(format!(
                "expected ledger rows for '{}' must be in sorted order",
                scenario.id
            )));
        }
    }
    Ok(())
}

impl fmt::Display for PosPack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {} ({} scenarios)",
            self.manifest.id,
            self.manifest.version,
            self.scenarios.len()
        )
    }
}
