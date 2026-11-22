#!/usr/bin/env python3
"""Gate for the POS-21 closed commercial kit.

Checks that the proprietary tree is git-ignored and untracked, that every
required product and legal document exists, that partner/price/SLA/training/demo
cross-references resolve, that the entitlement ledger and revocation register
agree, that no private key, credential or card-number-shaped fixture is present,
and that the draft state is honest: counsel review is pending and the release is
not signed off.

``--test`` also runs the workspace tests and the CLI status command.
``--require-reviewed`` fails while either legal template is still pending; use it
before an actual release, not in the draft state.

Exit code 0 means the draft tree is internally consistent. It does not mean
counsel reviewed anything, that a partner is appointed, or that a package is
saleable.
"""

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLOSED = ROOT / "closed" / "pos-commercial"

REQUIRED_DOCS = [
    "README.md",
    "oem-programme.md",
    "branding.md",
    "redistribution.md",
    "support-model.md",
    "indemnity-and-audit.md",
    "pricing.md",
    "entitlement-enforcement.md",
    "installation.md",
    "commissioning.md",
    "support-runbook.md",
    "training.md",
    "certification.md",
    "sla.md",
    "escalation.md",
    "demo-dataset.md",
    "sales-engineering.md",
    "security.md",
    "data-protection.md",
    "release-and-versioning.md",
    "partner-onboarding.md",
]
REQUIRED_DATA = [
    "data/partners.toml",
    "data/pricing.toml",
    "data/entitlements.toml",
    "data/revocations.toml",
    "data/sla.toml",
    "data/training/curriculum.toml",
    "data/training/installers.toml",
    "data/demo/dataset.toml",
]
REQUIRED_LEGAL = [
    "legal/oem-agreement.md",
    "legal/sla.md",
    "legal/review-record.toml",
    "release-manifest.toml",
    "trust/entitlement-public-key.toml",
]
REQUIRED_SOURCE = [
    "Cargo.toml",
    "LICENSE",
    "commercial-sdk/Cargo.toml",
    "commercial-sdk/src/lib.rs",
    "commercial-sdk/src/main.rs",
    "commercial-sdk/src/entitlement.rs",
    "commercial-sdk/src/partner.rs",
    "commercial-sdk/src/kit.rs",
    "commercial-sdk/src/sla.rs",
    "commercial-sdk/src/training.rs",
    "commercial-sdk/src/demo.rs",
    "commercial-sdk/src/activation.rs",
    "commercial-sdk/src/review.rs",
]

EXCLUDE_PARTS = {"target", "dist", ".git"}
FORBIDDEN_SUFFIXES = {
    ".pfx": "certificate/private-key container",
    ".p12": "certificate/private-key container",
    ".jks": "Java key store",
    ".keystore": "key store",
    ".pem": "key or certificate file",
}
CREDENTIAL_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "PEM private key"),
    (re.compile(r"(?i)private_key_hex\s*=\s*\"[0-9a-fA-F]{32,}\""), "private key hex"),
    (re.compile(r"\bsk_live_[A-Za-z0-9]{8,}"), "live secret key"),
    (re.compile(r"(?i)TIRBASE_[A-Z_]*(SECRET|KEY|PASSWORD|TOKEN)\s*=\s*\S{8,}"), "secret assignment"),
]
DIGIT_RUN = re.compile(r"\d{13,19}")
STUB = re.compile(r"\b(todo!|unimplemented!)\s*\(")
AGPL_CRATES = ["tirbase-pos", "tirbase-core", "tirbase-drivers", "tirbase-gateway"]


def run(command, cwd=ROOT):
    return subprocess.run(command, cwd=str(cwd), capture_output=True, text=True)


def luhn_valid(digits):
    total = 0
    parity = len(digits) % 2
    for index, character in enumerate(digits):
        value = int(character)
        if index % 2 == parity:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def load(path, problems):
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        problems.append(f"cannot parse {path.relative_to(ROOT)}: {error}")
        return {}


def check_files(problems):
    for relative in REQUIRED_DOCS:
        if not (CLOSED / "docs" / relative).is_file():
            problems.append(f"missing product document docs/{relative}")
    for relative in REQUIRED_DATA + REQUIRED_LEGAL + REQUIRED_SOURCE:
        if not (CLOSED / relative).is_file():
            problems.append(f"missing required file {relative}")


def check_partners(partners, pricing, curriculum, sla, problems):
    tiers = {tier["id"] for tier in pricing.get("tiers", [])}
    skus = {sku["id"] for sku in pricing.get("skus", [])}
    certifications = {
        row["id"] for row in curriculum.get("certifications", [])
    }
    sla_tiers = {tier["id"] for tier in sla.get("tiers", [])}
    seen = set()
    approved = 0
    for partner in partners.get("partners", []):
        pid = partner.get("id", "?")
        if pid in seen:
            problems.append(f"duplicate partner id {pid}")
        seen.add(pid)
        if not pid.startswith("PTR-"):
            problems.append(f"partner id {pid} does not use the PTR- prefix")
        if partner.get("status") == "approved":
            approved += 1
        if partner.get("tier") not in tiers:
            problems.append(f"{pid}: unknown price tier {partner.get('tier')!r}")
        if partner.get("support_tier") not in sla_tiers:
            problems.append(f"{pid}: unknown support tier {partner.get('support_tier')!r}")
        if not partner.get("regions"):
            problems.append(f"{pid}: no sale region")
        for sku in partner.get("skus", []):
            if sku not in skus:
                problems.append(f"{pid}: unknown SKU {sku}")
        for certification in partner.get("required_certifications", []):
            if certification not in certifications:
                problems.append(f"{pid}: unknown certification {certification}")
        if partner.get("redistribution") == "none" and partner.get("branding") == "white_label":
            problems.append(f"{pid}: white-label without redistribution right")
        if not partner.get("audit_rights"):
            problems.append(f"{pid}: audit_rights must be true for an OEM partner")
    if approved == 0:
        problems.append("no approved partner in the reference book")
    return seen


def check_pricing(pricing, sla, problems):
    tiers = {tier["id"]: tier for tier in pricing.get("tiers", [])}
    skus = {sku["id"]: sku for sku in pricing.get("skus", [])}
    sla_tiers = {tier["id"] for tier in sla.get("tiers", [])}
    for tier_id, tier in tiers.items():
        if tier.get("support_tier") not in sla_tiers:
            problems.append(f"price tier {tier_id}: unknown support tier")
        if tier.get("minimum_annual_minor", 0) < 0:
            problems.append(f"price tier {tier_id}: negative minimum")
    seen = set()
    for price in pricing.get("prices", []):
        key = (price.get("tier"), price.get("sku"))
        if key in seen:
            problems.append(f"duplicate price {key}")
        seen.add(key)
        if key[0] not in tiers or key[1] not in skus:
            problems.append(f"price names unknown tier/SKU {key}")
            continue
        sku = skus[key[1]]
        if not (0 < price.get("annual_minor", 0) <= sku.get("list_annual_minor", 0)):
            problems.append(f"price {key}: annual is not a positive discount of list")
        if not (0 <= price.get("per_deployment_minor", 0) <= sku.get("per_deployment_minor", 0)):
            problems.append(f"price {key}: per-deployment is not a discount of list")
    for tier_id in tiers:
        for sku_id in skus:
            if (tier_id, sku_id) not in seen:
                problems.append(f"no price for tier {tier_id} and SKU {sku_id}")


def check_sla(sla, problems):
    tier_ids = {tier["id"] for tier in sla.get("tiers", [])}
    severity_ids = {severity["id"] for severity in sla.get("severities", [])}
    targets = {(row.get("tier"), row.get("severity")) for row in sla.get("targets", [])}
    for tier_id in tier_ids:
        for severity_id in severity_ids:
            if (tier_id, severity_id) not in targets:
                problems.append(f"SLA missing target for {tier_id}/{severity_id}")
    for credit in sla.get("credits", []):
        if credit.get("tier") not in tier_ids:
            problems.append(f"SLA credit names unknown tier {credit.get('tier')}")
    if sla.get("timezone") != "UTC":
        problems.append("SLA clock must be UTC")


def check_ledger(entitlements, revocations, partners, pricing, problems):
    skus = {sku["id"]: sku for sku in pricing.get("skus", [])}
    partner_ids = {partner["id"] for partner in partners.get("partners", [])}
    records = {record["id"]: record for record in entitlements.get("entitlements", [])}
    if len(records) != len(entitlements.get("entitlements", [])):
        problems.append("duplicate entitlement id in the ledger")
    for record in records.values():
        eid = record.get("id", "?")
        if not eid.startswith("ENT-"):
            problems.append(f"{eid}: entitlement id does not use the ENT- prefix")
        if record.get("partner_id") not in partner_ids:
            problems.append(f"{eid}: unknown partner {record.get('partner_id')!r}")
            continue
        partner = next(
            row for row in partners["partners"] if row["id"] == record["partner_id"]
        )
        sku = skus.get(record.get("sku"))
        if sku is None:
            problems.append(f"{eid}: unknown SKU {record.get('sku')!r}")
        if record.get("deployments", 0) < 1 or record.get("deployments", 0) > partner.get(
            "max_deployments", 0
        ):
            problems.append(f"{eid}: deployment count outside the partner cap")
        for country in record.get("countries", []):
            if country not in partner.get("regions", []):
                problems.append(f"{eid}: country {country} outside the partner scope")
        if sku is not None:
            for feature in record.get("features", []):
                if feature not in sku.get("features", []):
                    problems.append(f"{eid}: feature {feature} not granted by {sku['id']}")
        status = record.get("status")
        if status == "draft":
            if record.get("token_path") or record.get("revoked_on"):
                problems.append(f"{eid}: draft carries a token or revocation")
        elif status == "issued":
            if not record.get("token_path"):
                problems.append(f"{eid}: issued without a token path")
            if record.get("revoked_on"):
                problems.append(f"{eid}: issued but carries a revocation")
        elif status == "revoked":
            if not record.get("revoked_on") or not record.get("revocation_reason"):
                problems.append(f"{eid}: revoked without a date and reason")
        else:
            problems.append(f"{eid}: unknown status {status!r}")
        if record.get("partner_id") == "PTR-IBERIA-03" and status != "revoked":
            # The suspended partner must not hold an issued entitlement.
            if status == "issued":
                problems.append(f"{eid}: issued to a suspended partner")
    revoked = revocations.get("revoked", [])
    if revocations.get("sequence", 0) < 1:
        problems.append("revocation register sequence must be positive")
    seen = set()
    for entry in revoked:
        rid = entry.get("entitlement_id")
        if rid in seen:
            problems.append(f"revocation register repeats {rid}")
        seen.add(rid)
        record = records.get(rid)
        if record is None:
            problems.append(f"revocation register names unknown entitlement {rid}")
        elif record.get("status") != "revoked":
            problems.append(f"{rid}: in revocation register but ledger status is not revoked")
        elif (
            record.get("revoked_on") != entry.get("revoked_on")
            or record.get("revocation_reason") != entry.get("reason")
        ):
            problems.append(f"{rid}: ledger and register disagree")
    for record in records.values():
        if record.get("status") == "revoked" and record.get("id") not in seen:
            problems.append(f"{record['id']}: revoked in ledger but absent from register")


def check_training(installers, partners, curriculum, as_of, problems):
    tracks = {track["id"] for track in curriculum.get("certifications", [])}
    for installer in installers.get("installers", []):
        iid = installer.get("id", "?")
        if installer.get("certification") not in tracks:
            problems.append(f"{iid}: unknown certification {installer.get('certification')!r}")
        if not installer.get("partner_id", "").startswith("PTR-"):
            problems.append(f"{iid}: no partner reference")
        if installer.get("certified_on", "") >= installer.get("expires_on", ""):
            problems.append(f"{iid}: expiry is not after certification")
        current = as_of <= installer.get("expires_on", "")
        status = installer.get("status")
        if status == "certified" and not current:
            problems.append(f"{iid}: certified but expired on {installer.get('expires_on')}")
        if status == "expired" and current:
            problems.append(f"{iid}: marked expired but still current")
    for partner in partners.get("partners", []):
        if partner.get("status") != "approved":
            continue
        for track in partner.get("required_certifications", []):
            held = any(
                installer.get("partner_id") == partner["id"]
                and installer.get("certification") == track
                and installer.get("status") == "certified"
                and as_of <= installer.get("expires_on", "")
                for installer in installers.get("installers", [])
            )
            if not held:
                problems.append(f"{partner['id']}: no current installer for {track}")


def check_demo(demo, problems):
    sites = {site["id"] for site in demo.get("sites", [])}
    terminals = {terminal["id"]: terminal for terminal in demo.get("terminals", [])}
    products = {product["sku"]: product for product in demo.get("products", [])}
    transactions = set()
    for transaction in demo.get("transactions", []):
        tid = transaction.get("id", "?")
        if tid in transactions:
            problems.append(f"duplicate demo transaction {tid}")
        transactions.add(tid)
        if transaction.get("site_id") not in sites:
            problems.append(f"{tid}: unknown site")
        terminal = terminals.get(transaction.get("terminal_id"))
        if terminal is None:
            problems.append(f"{tid}: unknown terminal")
        elif terminal.get("site_id") != transaction.get("site_id"):
            problems.append(f"{tid}: terminal belongs to another site")
        payment = transaction.get("payment")
        token = transaction.get("card_token", "")
        if payment == "cash" and token:
            problems.append(f"{tid}: cash sale carries a token")
        if payment == "card_token":
            if not token.startswith("tok_") or len(token) < 8:
                problems.append(f"{tid}: card sale has no token reference")
            if re.search(r"\d{13,}", token):
                problems.append(f"{tid}: token contains a card-number-shaped run")
        subtotal = 0
        tax = 0
        for line in transaction.get("lines", []):
            product = products.get(line.get("sku"))
            if product is None:
                problems.append(f"{tid}: unknown product {line.get('sku')!r}")
                continue
            quantity = line.get("quantity", 0)
            if not 1 <= quantity <= 1000:
                problems.append(f"{tid}: line quantity outside 1..=1000")
                continue
            amount = product["unit_price_minor"] * quantity
            subtotal += amount
            tax += (amount * product["tax_bps"] + 5_000) // 10_000
        if transaction.get("subtotal_minor") != subtotal:
            problems.append(f"{tid}: subtotal does not re-derive")
        if transaction.get("tax_minor") != tax:
            problems.append(f"{tid}: tax does not re-derive")
        if transaction.get("total_minor") != subtotal + tax:
            problems.append(f"{tid}: total does not re-derive")
    scenarios = set()
    for scenario in demo.get("scenarios", []):
        sid = scenario.get("id", "?")
        if sid in scenarios:
            problems.append(f"duplicate demo scenario {sid}")
        scenarios.add(sid)
        for tid in scenario.get("transactions", []):
            if tid not in transactions:
                problems.append(f"{sid}: unknown transaction {tid}")
        if not scenario.get("steps") or not scenario.get("expected"):
            problems.append(f"{sid}: missing steps or expected result")


def check_review(review, release, problems, require_reviewed):
    documents = {document.get("id"): document for document in review.get("documents", [])}
    approved = 0
    for did, document in documents.items():
        path = CLOSED / document.get("path", "")
        if not path.is_file():
            problems.append(f"review document {did}: missing {document.get('path')}")
        status = document.get("status")
        if status == "pending":
            if document.get("reviewer") or document.get("counsel_firm") or document.get(
                "reviewed_on"
            ):
                problems.append(f"{did}: pending review names a reviewer or date")
        elif status == "approved":
            approved += 1
            if not document.get("reviewer") or not document.get("counsel_firm"):
                problems.append(f"{did}: approved without reviewer and firm")
            if not document.get("reviewed_on"):
                problems.append(f"{did}: approved without a review date")
            if not document.get("scope"):
                problems.append(f"{did}: approved without a review scope")
        elif status == "rejected":
            if not document.get("comments"):
                problems.append(f"{did}: rejected without comments")
        else:
            problems.append(f"{did}: unknown review status {status!r}")
    if "oem-agreement" not in documents:
        problems.append("review record does not name the OEM agreement")
    if "sla" not in documents:
        problems.append("review record does not name the SLA")
    if require_reviewed and approved != len(documents):
        problems.append("--require-reviewed: counsel review is not complete")
    if release.get("status") == "draft":
        if release.get("signed_off"):
            problems.append("draft release is signed off")
    elif release.get("status") == "release":
        if not release.get("signed_off"):
            problems.append("release is not signed off")
        if approved != len(documents) or not documents:
            problems.append("release is final while counsel review is incomplete")
        anchor = CLOSED / "trust" / "entitlement-public-key.toml"
        anchor_data = load(anchor, problems)
        if anchor_data.get("key_id") == "UNPROVISIONED":
            problems.append("release is final but the trust anchor is unprovisioned")
        if len(anchor_data.get("public_key_hex", "")) != 64:
            problems.append("release is final but the trust anchor has no public key")
    else:
        problems.append(f"release manifest has unknown status {release.get('status')!r}")


def check_tree(problems):
    ignored = run(["git", "check-ignore", "-q", "closed/pos-commercial/Cargo.toml"])
    if ignored.returncode != 0:
        problems.append("closed/pos-commercial is not git-ignored")
    tracked = run(["git", "ls-files", "closed"])
    if tracked.stdout.strip():
        problems.append("closed/ contains tracked files: " + tracked.stdout.strip().splitlines()[0])
    manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    if "closed/" in manifest:
        problems.append("root Cargo.toml references closed/")

    for path in CLOSED.rglob("*"):
        relative = path.relative_to(CLOSED)
        if EXCLUDE_PARTS & set(relative.parts):
            continue
        if path.is_dir():
            continue
        suffix = path.suffix.lower()
        if suffix in FORBIDDEN_SUFFIXES:
            problems.append(
                f"{FORBIDDEN_SUFFIXES[suffix]}: {path.relative_to(ROOT)}"
            )
        if path.stat().st_size > 2_000_000:
            problems.append(f"unexpected large file: {path.relative_to(ROOT)}")
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for pattern, label in CREDENTIAL_PATTERNS:
            if pattern.search(text):
                problems.append(f"{label} in {path.relative_to(ROOT)}")
        if path.suffix in {".rs", ".json", ".md", ".toml", ".py"}:
            for match in DIGIT_RUN.findall(text):
                if len(set(match)) == 1:
                    continue
                if luhn_valid(match):
                    problems.append(f"Luhn-valid card-number shape in {path.relative_to(ROOT)}")
                    break
        if path.suffix == ".rs" and STUB.search(text):
            problems.append(f"stub left in {path.relative_to(ROOT)}")

    for path in CLOSED.rglob("Cargo.toml"):
        text = path.read_text(encoding="utf-8")
        for crate in AGPL_CRATES:
            if re.search(rf"(?m)^\s*{re.escape(crate)}\s*=", text):
                problems.append(f"AGPL dependency {crate} in {path.relative_to(ROOT)}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--test", action="store_true", help="run tests and CLI status")
    parser.add_argument(
        "--require-reviewed",
        action="store_true",
        help="fail unless counsel review is complete (release use only)",
    )
    args = parser.parse_args()

    if not CLOSED.is_dir():
        print("closed commercial tree absent; nothing to check")
        return 0

    problems = []
    check_files(problems)
    partners = load(CLOSED / "data/partners.toml", problems)
    pricing = load(CLOSED / "data/pricing.toml", problems)
    sla = load(CLOSED / "data/sla.toml", problems)
    curriculum = load(CLOSED / "data/training/curriculum.toml", problems)
    installers = load(CLOSED / "data/training/installers.toml", problems)
    entitlements = load(CLOSED / "data/entitlements.toml", problems)
    revocations = load(CLOSED / "data/revocations.toml", problems)
    demo = load(CLOSED / "data/demo/dataset.toml", problems)
    review = load(CLOSED / "legal/review-record.toml", problems)
    release = load(CLOSED / "release-manifest.toml", problems)

    check_partners(partners, pricing, curriculum, sla, problems)
    check_pricing(pricing, sla, problems)
    check_sla(sla, problems)
    check_ledger(entitlements, revocations, partners, pricing, problems)
    as_of = release.get("as_of") or review.get("as_of") or "1970-01-01"
    check_training(installers, partners, curriculum, as_of, problems)
    check_demo(demo, problems)
    check_review(review, release, problems, args.require_reviewed)
    check_tree(problems)

    print(f"closed tree: {CLOSED.relative_to(ROOT)}")
    print(f"documents: {len(REQUIRED_DOCS)} product docs + {len(REQUIRED_LEGAL)} legal/release files")
    print(
        f"data: {len(partners.get('partners', []))} partners, "
        f"{len(entitlements.get('entitlements', []))} entitlements, "
        f"{len(demo.get('transactions', []))} demo transactions"
    )

    if problems:
        for problem in problems:
            print(f"FAIL {problem}")
        return 1

    print("PASS required files present; partner, price, SLA and training references resolve")
    print("PASS ledger and revocation register agree; demo totals re-derive")
    print("PASS no private key, credential, AGPL dependency or card-number shape")
    pending = [
        document.get("id")
        for document in review.get("documents", [])
        if document.get("status") != "approved"
    ]
    if pending:
        print(f"PASS draft state honest: counsel review pending for {', '.join(pending)}")
        print("PASS release is not signed off and may not be sold")
    else:
        print("PASS counsel review recorded for every legal document")

    if args.test:
        result = subprocess.run(
            ["cargo", "test", "--workspace", "--no-fail-fast"],
            cwd=str(CLOSED),
            text=True,
        )
        if result.returncode != 0:
            print("FAIL workspace tests")
            return 1
        print("PASS workspace tests")
        status = run(
            ["cargo", "run", "--quiet", "--bin", "pos-commercial", "--", "status", "--root", "."],
            cwd=CLOSED,
        )
        if status.returncode != 0:
            print("FAIL CLI status")
            print(status.stderr.strip())
            return 1
        print("PASS CLI status")
        if pending and "PENDING" not in status.stdout:
            print("FAIL CLI status does not report pending counsel review")
            return 1
        if release.get("status") == "draft" and "NOT signed off" not in status.stdout:
            print("FAIL CLI status does not report the unsigned draft release")
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
