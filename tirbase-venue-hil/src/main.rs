// SPDX-License-Identifier: AGPL-3.0-only

use std::env;
use std::path::PathBuf;

fn main() -> std::io::Result<()> {
    let mut out = PathBuf::from("target/hil-evidence/st12");
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--out" {
            if let Some(path) = args.next() {
                out = PathBuf::from(path);
            }
        }
    }
    std::fs::create_dir_all(&out)?;
    let seed = tirbase_venue_hil::campaign::REFERENCE_SEED;
    let report = tirbase_venue_hil::run_campaign(seed);
    std::fs::write(out.join("campaign.json"), report.to_json())?;
    std::fs::write(out.join("campaign.md"), report.to_markdown())?;
    println!(
        "ST-12 venue gate HIL campaign: {} case(s), digest {}, {} -> {}",
        report.cases.len(),
        report.digest,
        if report.passed { "PASS" } else { "FAIL" },
        out.display()
    );
    if report.passed {
        Ok(())
    } else {
        Err(std::io::Error::other("ST-12 campaign failed"))
    }
}
