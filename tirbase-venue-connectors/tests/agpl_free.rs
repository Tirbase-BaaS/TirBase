// SPDX-License-Identifier: Apache-2.0

//! Dependency proof: the venue connector framework is AGPL-free.
//!
//! A closed venue connector links this crate (and through it the Apache-2.0
//! `tirbase-integrations` framework) only. This test walks the resolved
//! dependency graph in `Cargo.lock` from `tirbase-venue-connectors` and fails if
//! any AGPL-licensed first-party crate is reachable — including every
//! `tirbase-venue*` runtime crate from ST-02..ST-09.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// AGPL-3.0-only first-party crates from LICENSING.md and the venue runtime.
const AGPL_WORKSPACE_CRATES: &[&str] = &[
    "tirbase-admin",
    "tirbase-core",
    "tirbase-demo",
    "tirbase-drivers",
    "tirbase-gateway",
    "tirbase-guard",
    "tirbase-pos",
    "tirbase-sim",
    "tirbase-venue",
    "tirbase-venue-gateway",
    "tirbase-venue-access",
    "tirbase-venue-gate",
    "tirbase-venue-ticket",
    "tirbase-venue-capacity",
    "tirbase-venue-admission",
    "tirbase-venue-lockdown",
    "tirbase-venue-scenario-runner",
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
            if !value.trim().starts_with(']') {
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
    let manifest = read("tirbase-venue-connectors/Cargo.toml");
    assert!(
        manifest.contains("license = \"Apache-2.0\""),
        "the venue connector framework must be Apache-2.0"
    );
    for dependency in direct_dependencies(&manifest) {
        assert!(
            !AGPL_WORKSPACE_CRATES.contains(&dependency.as_str()),
            "the framework must not depend on AGPL crate '{dependency}'"
        );
        if dependency.starts_with("tirbase-") {
            assert_eq!(
                dependency, "tirbase-integrations",
                "the only first-party dependency may be the Apache-2.0 integration framework, found '{dependency}'"
            );
        }
    }
}

#[test]
fn resolved_dependency_graph_is_agpl_free() {
    let graph = parse_lock(&read("Cargo.lock"));
    let reachable = reachable(&graph, "tirbase-venue-connectors");

    for expected in ["serde_json", "sha2", "toml", "tirbase-integrations"] {
        assert!(
            reachable.contains(expected),
            "expected tirbase-venue-connectors -> {expected} in the graph, got {reachable:?}"
        );
    }

    let violations: Vec<&String> = reachable
        .iter()
        .filter(|package| AGPL_WORKSPACE_CRATES.contains(&package.as_str()))
        .collect();
    assert!(
        violations.is_empty(),
        "tirbase-venue-connectors reaches AGPL crates: {violations:?}"
    );

    // No AGPL venue runtime crate is even reachable transitively. This crate
    // itself is Apache-2.0 and is the only `tirbase-venue*` package in the graph.
    assert!(!reachable.iter().any(
        |package| package.starts_with("tirbase-venue") && package != "tirbase-venue-connectors"
    ));
}

#[test]
fn licensing_matrix_lists_the_framework_as_apache() {
    let matrix = read("LICENSING.md");
    let row = matrix
        .lines()
        .find(|line| line.contains("`tirbase-venue-connectors`"))
        .expect("LICENSING.md must carry a tirbase-venue-connectors row");
    assert!(
        row.contains("`Apache-2.0`"),
        "tirbase-venue-connectors row must be Apache-2.0: {row}"
    );
}
