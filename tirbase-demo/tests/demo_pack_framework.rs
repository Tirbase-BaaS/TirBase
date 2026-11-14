// SPDX-License-Identifier: Apache-2.0

//! Demo pack framework checks (CLAIM-46.1, CLAIM-47.3, PV-16).

use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

#[test]
fn cold_chain_pack_matches_demo_pack_format() {
    let pack = workspace_root().join("tirbase-demo/cold-chain");
    assert!(
        tirbase_demo::pack_has_required_layout(&pack, tirbase_demo::COLD_CHAIN_PACK_FORMAT),
        "cold-chain pack missing required layout entries: {:?}",
        tirbase_demo::COLD_CHAIN_PACK_FORMAT
    );
    for rel in tirbase_demo::DEMO_PACK_FORMAT {
        assert!(pack.join(rel).exists(), "missing demo-pack format entry: {rel}");
    }
}

#[test]
fn cold_chain_readme_documents_non_goals() {
    let readme = workspace_root().join("docs/demo/cold-chain/README.md");
    let text = std::fs::read_to_string(&readme).expect("read docs/demo/cold-chain/README.md");
    assert!(
        text.contains("What TirBase does not protect against in this scenario"),
        "cold-chain README must contain the required non-goals section"
    );
    let pack_readme = workspace_root().join("tirbase-demo/cold-chain/docs/README.md");
    let pack_text = std::fs::read_to_string(&pack_readme).expect("read pack README");
    assert!(
        pack_text.contains("What TirBase does not protect against in this scenario"),
        "pack README must contain the required non-goals section"
    );
}
