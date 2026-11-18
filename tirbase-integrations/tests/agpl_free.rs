// SPDX-License-Identifier: Apache-2.0

//! Dependency proof: `tirbase-integrations` is AGPL-free.
//!
//! A vendor connector links this crate only. This test walks the resolved
//! dependency graph recorded in the workspace `Cargo.lock` from
//! `tirbase-integrations` and fails if any AGPL-licensed first-party runtime
//! crate is reachable. It also checks the manifest declares Apache-2.0 and no
//! AGPL crate directly, and keeps the denylist honest against `LICENSING.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// AGPL-3.0-only first-party crates from LICENSING.md.
const AGPL_WORKSPACE_CRATES: &[&str] = &[
    "tirbase-admin",
    "tirbase-core",
    "tirbase-demo",
    "tirbase-drivers",
    "tirbase-gateway",
    "tirbase-guard",
    "tirbase-pos",
    "tirbase-sim",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate lives under the workspace root")
        .to_path_buf()
}

fn read(relative: &str) -> String {
    let path = workspace_root().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// Minimal `Cargo.lock` parser: package blocks and their dependency names.
fn parse_lock(contents: &str) -> BTreeMap<String, BTreeSet<String>> {
    fn flush(
        graph: &mut BTreeMap<String, BTreeSet<String>>,
        name: &mut Option<String>,
        deps: &mut BTreeSet<String>,
    ) {
        if let Some(package) = name.take() {
            graph
                .entry(package)
                .or_default()
                .extend(std::mem::take(deps));
        }
    }

    let mut graph: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut name: Option<String> = None;
    let mut deps: BTreeSet<String> = BTreeSet::new();
    let mut in_block = false;
    let mut in_dependencies = false;

    for line in contents.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            flush(&mut graph, &mut name, &mut deps);
            in_block = true;
            in_dependencies = false;
            continue;
        }
        if !in_block {
            continue;
        }
        if in_dependencies {
            if line.starts_with(']') {
                in_dependencies = false;
                continue;
            }
            let entry = line.trim_end_matches(',').trim().trim_matches('"');
            if let Some(dependency) = entry.split_whitespace().next() {
                deps.insert(dependency.to_string());
            }
            continue;
        }
        if let Some(value) = line.strip_prefix("name = ") {
            name = Some(value.trim().trim_matches('"').to_string());
        } else if let Some(value) = line.strip_prefix("dependencies = [") {
            let inline = value.trim();
            if !inline.starts_with(']') {
                in_dependencies = true;
            }
        }
    }
    flush(&mut graph, &mut name, &mut deps);
    graph
}

/// Direct `[dependencies]` keys from a manifest (ignores table headers).
fn direct_dependencies(manifest: &str) -> Vec<String> {
    let mut dependencies = Vec::new();
    let mut in_dependencies = false;
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_dependencies = line == "[dependencies]";
            continue;
        }
        if !in_dependencies || line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, _)) = line.split_once('=') {
            dependencies.push(key.trim().to_string());
        }
    }
    dependencies
}

fn reachable(graph: &BTreeMap<String, BTreeSet<String>>, root: &str) -> BTreeSet<String> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut stack = vec![root.to_string()];
    while let Some(package) = stack.pop() {
        if !seen.insert(package.clone()) {
            continue;
        }
        let deps = graph
            .get(&package)
            .unwrap_or_else(|| panic!("package '{package}' is missing from Cargo.lock"));
        for dep in deps {
            if !graph.contains_key(dep) {
                panic!("dependency '{dep}' of '{package}' is missing from Cargo.lock");
            }
            stack.push(dep.clone());
        }
    }
    seen
}

#[test]
fn crate_declares_apache_licence_and_no_agpl_direct_dependency() {
    let manifest = read("tirbase-integrations/Cargo.toml");
    assert!(
        manifest.contains("license = \"Apache-2.0\""),
        "tirbase-integrations must be Apache-2.0"
    );
    for dependency in direct_dependencies(&manifest) {
        assert!(
            !AGPL_WORKSPACE_CRATES.contains(&dependency.as_str()),
            "tirbase-integrations must not depend on AGPL crate '{dependency}'"
        );
        assert!(
            !dependency.starts_with("tirbase-"),
            "the framework crate must not depend on any first-party TirBase crate, found '{dependency}'"
        );
    }
}

#[test]
fn resolved_dependency_graph_is_agpl_free() {
    let graph = parse_lock(&read("Cargo.lock"));
    let reachable = reachable(&graph, "tirbase-integrations");

    for expected in ["reqwest", "serde_json", "sha2", "toml"] {
        assert!(
            reachable.contains(expected),
            "expected tirbase-integrations -> {expected} in the graph, got {reachable:?}"
        );
    }

    let violations: Vec<&String> = reachable
        .iter()
        .filter(|package| AGPL_WORKSPACE_CRATES.contains(&package.as_str()))
        .collect();
    assert!(
        violations.is_empty(),
        "tirbase-integrations reaches AGPL crates: {violations:?}"
    );
}

/// Keeps `AGPL_WORKSPACE_CRATES` honest: every AGPL row in the matrix must be
/// listed above, or the test would silently stop covering a new AGPL crate.
#[test]
fn agpl_denylist_matches_licensing_matrix() {
    let matrix = read("LICENSING.md");
    let mut matrix_agpl: BTreeSet<String> = BTreeSet::new();
    for line in matrix.lines() {
        let line = line.trim();
        if !line.starts_with('|') {
            continue;
        }
        let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
        if cells.len() < 3 || !cells[2].contains("AGPL-3.0-only") {
            continue;
        }
        for token in cells[1].split('`').skip(1).step_by(2) {
            let token = token.trim().trim_end_matches('/');
            if token.starts_with("tirbase-") && !token.contains('/') && !token.contains('*') {
                matrix_agpl.insert(token.to_string());
            }
        }
    }
    for crate_name in &matrix_agpl {
        assert!(
            AGPL_WORKSPACE_CRATES.contains(&crate_name.as_str()),
            "LICENSING.md lists AGPL crate '{crate_name}' but the AGPL denylist does not"
        );
    }
}

/// The matrix must list this crate as Apache-2.0, otherwise the licence gate
/// (`scripts/check-licence-matrix.py`) fails.
#[test]
fn licensing_matrix_lists_the_framework_as_apache() {
    let matrix = read("LICENSING.md");
    let row = matrix
        .lines()
        .find(|line| line.contains("`tirbase-integrations`"))
        .expect("LICENSING.md must carry a tirbase-integrations row");
    assert!(
        row.contains("`Apache-2.0`"),
        "tirbase-integrations row must be Apache-2.0: {row}"
    );
}
