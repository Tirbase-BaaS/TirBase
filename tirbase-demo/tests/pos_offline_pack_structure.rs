// SPDX-License-Identifier: Apache-2.0

//! Structural checks for the offline POS pack (POS-09).
//!
//! Apache-licensed: these tests read the pack as data and never link the POS
//! runtime. They prove the manifest, scenarios, approvals, expected outcomes
//! and docs are complete and consistent, and that the pack is data-only.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use tirbase_demo::pos_pack::{
    load_pos_pack, PosPack, POS_PACK_LICENCE, POS_PACK_REQUIRED_SCENARIOS, POS_PACK_SCHEMA_VERSION,
};

const PACK_FILES: &[&str] = &[
    "pack.toml",
    "expected/outcomes.toml",
    "sim/config.toml",
    "run.sh",
    "docs/README.md",
    "docs/non-goals.md",
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn pack_root() -> PathBuf {
    workspace_root().join("tirbase-demo/pos-offline")
}

fn pack() -> PosPack {
    load_pos_pack(pack_root()).expect("offline POS pack must load and validate")
}

#[test]
fn pack_manifest_is_versioned_and_identifies_the_directory() {
    let pack = pack();
    assert_eq!(pack.manifest.schema_version, POS_PACK_SCHEMA_VERSION);
    assert_eq!(pack.manifest.id, "pos-offline");
    assert_eq!(pack.manifest.version, "1.0.0");
    assert_eq!(pack.manifest.licence, POS_PACK_LICENCE);
    assert_eq!(pack.manifest.kind, "pos_offline");
    assert_eq!(pack.manifest.run, "run.sh");
    assert_eq!(pack.scenarios.len(), POS_PACK_REQUIRED_SCENARIOS.len());
}

#[test]
fn pack_declares_the_six_required_scenarios() {
    let pack = pack();
    let ids: BTreeSet<&str> = pack
        .scenarios
        .iter()
        .map(|scenario| scenario.id.as_str())
        .collect();
    let expected: BTreeSet<&str> = POS_PACK_REQUIRED_SCENARIOS.iter().copied().collect();
    assert_eq!(ids, expected);
    for scenario in &pack.scenarios {
        assert!(
            pack.outcome(&scenario.id).is_some(),
            "scenario '{}' has no expected outcome",
            scenario.id
        );
    }
}

#[test]
fn every_scenario_declares_state_timeline_commands_approvals_and_invariant() {
    let pack = pack();
    for scenario in &pack.scenarios {
        assert!(!scenario.initial.currency.is_empty());
        assert!(!scenario.initial.terminal.is_empty());
        assert!(!scenario.initial.operator.is_empty());
        assert!(!scenario.initial.check.is_empty());
        assert!(scenario.initial.epoch > 0);
        assert!(scenario.initial.check_total_minor > 0);
        assert!(!scenario.partitions.is_empty());
        assert!(!scenario.commands.is_empty());
        assert!(!scenario.invariant.is_empty());
        for partition in &scenario.partitions {
            assert!(partition.offline);
            assert!(partition.to_ms > partition.from_ms);
            assert!(!partition.reason.is_empty());
        }
        for command in &scenario.commands {
            assert!(!command.id.is_empty());
            assert!(!command.actor.is_empty());
            assert!(command.at_ms >= 0);
        }
        for approval in &scenario.approvals {
            assert!(!approval.id.is_empty());
            assert!(approval.amount_minor > 0);
            assert!(approval.expires_at_ms > approval.requested_at_ms);
            assert_ne!(
                approval.requester, approval.approver,
                "approvals must not self-approve"
            );
        }
    }
}

#[test]
fn permits_and_ledger_rows_cover_each_command() {
    let pack = pack();
    for scenario in &pack.scenarios {
        let outcome = pack.outcome(&scenario.id).expect("outcome coverage");
        assert_eq!(
            outcome.permit.len(),
            scenario.commands.len(),
            "scenario '{}' must declare one permit per command",
            scenario.id
        );
        for (command, permit) in scenario.commands.iter().zip(&outcome.permit) {
            assert_eq!(&command.expect, permit);
        }
        assert!(!outcome.ledger.is_empty());
        for row in &outcome.ledger {
            let (key, value) = row.split_once('=').expect("ledger row is key=value");
            assert!(!key.is_empty() && !value.is_empty());
        }
    }
}

#[test]
fn scenario_specific_state_is_declared_where_needed() {
    let pack = pack();

    let pricing = pack
        .scenario("offline_price_change")
        .and_then(|scenario| scenario.initial.pricing.as_ref())
        .expect("pricing state");
    assert!(pricing.old_price_minor < pricing.new_price_minor);
    assert!(pricing.new_effective_ms > 0);

    let split = pack
        .scenario("split_bill_conflict")
        .and_then(|scenario| scenario.initial.split.as_ref())
        .expect("split state");
    assert_ne!(split.target_a, split.target_b);

    let kds = pack
        .scenario("duplicate_kds_ticket")
        .and_then(|scenario| scenario.initial.kds.as_ref())
        .expect("KDS state");
    assert!(kds.quantity_thousandths > 0);
    assert_eq!(kds.station, "grill");
}

#[test]
fn pack_declares_every_layout_file() {
    for relative in PACK_FILES {
        assert!(
            pack_root().join(relative).is_file(),
            "offline POS pack missing {relative}"
        );
    }
    let manifest = &pack().manifest;
    for relative in manifest
        .scenarios
        .iter()
        .chain(manifest.docs.iter())
        .chain(std::iter::once(&manifest.expected))
        .chain(std::iter::once(&manifest.run))
    {
        assert!(
            tirbase_demo::safe_pack_path(&pack_root(), relative).is_ok(),
            "manifest reference {relative} must resolve inside the pack"
        );
    }
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read pack directory") {
        let entry = entry.expect("pack directory entry");
        let path = entry.path();
        let metadata = std::fs::symlink_metadata(&path).expect("pack file metadata");
        assert!(
            !metadata.file_type().is_symlink(),
            "pack must not contain symlinks: {}",
            path.display()
        );
        if metadata.is_dir() {
            collect_files(&path, out);
        } else {
            out.push(path);
        }
    }
}

#[test]
fn pack_contains_no_executable_code() {
    let mut files = Vec::new();
    collect_files(&pack_root(), &mut files);
    assert!(!files.is_empty());

    let allowed: BTreeSet<&str> = ["toml", "md"].into_iter().collect();
    for path in &files {
        let relative = path
            .strip_prefix(pack_root())
            .expect("pack-relative path")
            .to_string_lossy()
            .replace('\\', "/");

        if relative == "run.sh" {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(path)
                    .expect("launcher metadata")
                    .permissions();
                assert!(
                    mode.mode() & 0o111 != 0,
                    "run.sh must be executable so the pack can be launched"
                );
            }
            continue;
        }

        let extension = path
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or_default();
        assert!(
            allowed.contains(extension),
            "pack file '{relative}' is not data (allowed: .toml, .md, run.sh)"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path)
                .expect("pack file metadata")
                .permissions();
            assert_eq!(
                mode.mode() & 0o111,
                0,
                "pack file '{relative}' must not be executable"
            );
        }

        let text = std::fs::read_to_string(path).expect("pack file is UTF-8 text");
        assert!(
            !text.starts_with("#!"),
            "pack file '{relative}' must not be a script"
        );
    }
}

#[test]
fn pack_documents_the_required_non_goals() {
    let readme = std::fs::read_to_string(pack_root().join("docs/README.md"))
        .expect("read pack README")
        .to_lowercase();
    assert!(readme.contains("data only"));
    assert!(readme.contains("pos-02"));
    assert!(readme.contains("pos-08"));

    let non_goals = std::fs::read_to_string(pack_root().join("docs/non-goals.md"))
        .expect("read non-goals")
        .to_lowercase();
    for required in [
        "no fiscal certification",
        "no pci scope reduction",
        "no acquirer settlement",
    ] {
        assert!(
            non_goals.contains(required),
            "docs/non-goals.md must state '{required}'"
        );
    }
}
