#!/usr/bin/env python3
"""Build a source-free partner package for the POS-21 commercial kit.

The package contains the compiled ``pos-commercial`` binary, product
documentation, the two legal templates, the demo dataset, the public trust
anchor and the proprietary licence. It never contains Rust source, Cargo files,
tests, internal pricing/partner ledgers, private keys or production tokens.

``--draft`` (the default) produces a clearly watermarked package that may be used
for a sandbox or a partner evaluation. ``--release`` refuses while counsel review
is pending, while the release manifest is not final and signed off, or while the
trust anchor is unprovisioned; it also requires a detached signature file from
the release authority.

The package carries a SHA-256 manifest. A draft is not saleable, and an unsigned
draft is not evidence that a partner release was authorised.
"""

import argparse
import hashlib
import shutil
import subprocess
import sys
import tarfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLOSED = ROOT / "closed" / "pos-commercial"
DIST = CLOSED / "dist"

FORBIDDEN_SUFFIXES = {".rs", ".rlib", ".rmeta", ".pdb", ".pem", ".key", ".poskey"}
FORBIDDEN_NAMES = {"Cargo.toml", "Cargo.lock", ".env", ".gitignore", ".git"}
FORBIDDEN_DIRS = {"src", "tests", "target", "benches", "examples", ".git", ".cargo"}

ALLOWED_DOCS = None  # every docs/*.md is included
ALLOWED_LEGAL = {"oem-agreement.md", "sla.md"}
ALLOWED_DATA = {"dataset.toml"}
ALLOWED_TRUST = {"entitlement-public-key.toml"}


def fail(message):
    print(f"FAIL {message}")
    return 1


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_toml(path):
    return tomllib.loads(path.read_text(encoding="utf-8"))


def check_release_ready():
    review = load_toml(CLOSED / "legal/review-record.toml")
    release = load_toml(CLOSED / "release-manifest.toml")
    anchor = load_toml(CLOSED / "trust/entitlement-public-key.toml")
    problems = []
    pending = [
        document["id"]
        for document in review.get("documents", [])
        if document.get("status") != "approved"
    ]
    if pending:
        problems.append("counsel review pending for " + ", ".join(pending))
    if release.get("status") != "release":
        problems.append("release manifest is not in release state")
    if not release.get("signed_off"):
        problems.append("release manifest is not signed off")
    if anchor.get("key_id") == "UNPROVISIONED" or len(anchor.get("public_key_hex", "")) != 64:
        problems.append("trust anchor is not provisioned")
    return problems


def copy_file(source, destination, relative):
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    return relative


def stage(stage_dir, version, draft):
    contents = []
    binary = CLOSED / "target" / "release" / "pos-commercial"
    if not binary.is_file():
        raise SystemExit("release binary is missing; run cargo build --release first")
    contents.append(copy_file(binary, stage_dir / "bin/pos-commercial", "bin/pos-commercial"))

    for source in sorted((CLOSED / "docs").glob("*.md")):
        relative = f"docs/{source.name}"
        contents.append(copy_file(source, stage_dir / relative, relative))

    for name in sorted(ALLOWED_LEGAL):
        source = CLOSED / "legal" / name
        if not source.is_file():
            raise SystemExit(f"legal template missing: {source}")
        relative = f"legal/{name}"
        contents.append(copy_file(source, stage_dir / relative, relative))

    demo = CLOSED / "data" / "demo" / "dataset.toml"
    contents.append(copy_file(demo, stage_dir / "data/demo/dataset.toml", "data/demo/dataset.toml"))

    anchor = CLOSED / "trust" / "entitlement-public-key.toml"
    contents.append(
        copy_file(anchor, stage_dir / "trust/entitlement-public-key.toml", "trust/entitlement-public-key.toml")
    )
    contents.append(copy_file(CLOSED / "LICENSE", stage_dir / "LICENSE", "LICENSE"))

    if draft:
        marker = stage_dir / "DRAFT-NOT-FOR-DISTRIBUTION.txt"
        marker.write_text(
            "DRAFT PACKAGE — NOT FOR PARTNER DISTRIBUTION OR SALE\n\n"
            "Counsel review of the OEM and SLA templates is pending. The trust\n"
            "anchor may be unprovisioned and the package is unsigned. Use only in\n"
            "a sandbox for evaluation.\n",
            encoding="utf-8",
        )
        contents.append("DRAFT-NOT-FOR-DISTRIBUTION.txt")

    stage_dir.mkdir(parents=True, exist_ok=True)
    for relative in contents:
        path = stage_dir / relative
        if not path.is_file():
            raise SystemExit(f"staged file missing: {relative}")
    return sorted(contents)


def inspect(stage_dir, contents, problems):
    for path in stage_dir.rglob("*"):
        relative = path.relative_to(stage_dir)
        if path.is_symlink():
            problems.append(f"symlink in package: {relative}")
            continue
        if path.is_dir():
            if path.name in FORBIDDEN_DIRS:
                problems.append(f"forbidden directory in package: {relative}")
            continue
        if path.name in FORBIDDEN_NAMES:
            problems.append(f"forbidden file in package: {relative}")
        if path.suffix.lower() in FORBIDDEN_SUFFIXES:
            problems.append(f"forbidden source/key file in package: {relative}")
        if relative.as_posix() not in contents and relative.as_posix() not in {
            "MANIFEST.toml",
            "SHA256SUMS",
        }:
            problems.append(f"file outside the package allowlist: {relative}")
        if path.stat().st_size > 20_000_000:
            problems.append(f"unexpected large file in package: {relative}")

    for required in ["bin/pos-commercial", "LICENSE", "docs/README.md"]:
        if not (stage_dir / required).is_file():
            problems.append(f"package is missing {required}")


def write_manifest(stage_dir, version, draft, release, contents):
    lines = [
        "schema_version = 1",
        f'package = "pos-commercial"',
        f'version = "{version}"',
        (
            'distribution = "draft_only"'
            if draft
            else 'distribution = "partner_release"'
        ),
        f'release_state = "{"draft" if draft else "release"}"',
        f'as_of = "{release.get("as_of", "1970-01-01")}"',
        "source_free = true",
        f'watermark = "{"DRAFT — not for partner distribution" if draft else ""}"',
        'integrity = "sha256"',
        'signature = "unsigned-draft"' if draft else 'signature = "detached"',
        "",
        "[[files]]",
    ]
    manifest_path = stage_dir / "MANIFEST.toml"
    for relative in contents:
        lines.append(f'path = "{relative}"')
        lines.append(f'sha256 = "{sha256(stage_dir / relative)}"')
        lines.append("")
        lines.append("[[files]]")
    lines.pop()  # trailing [[files]]
    manifest_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    sums = []
    for path in sorted(stage_dir.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            sums.append(f"{sha256(path)}  {path.relative_to(stage_dir).as_posix()}")
    (stage_dir / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")


def make_tarball(stage_dir, archive):
    if archive.exists():
        archive.unlink()
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(stage_dir, arcname=stage_dir.name)
    return archive


def main():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--draft", action="store_true", help="build a watermarked draft package (default)")
    mode.add_argument("--release", action="store_true", help="build a release package")
    parser.add_argument("--signature", type=Path, help="detached signature over MANIFEST.toml (release only)")
    args = parser.parse_args()

    if not CLOSED.is_dir():
        return fail("closed commercial tree is absent")
    release = load_toml(CLOSED / "release-manifest.toml")
    version = release.get("release", "pos-commercial-0.0.0")
    draft = not args.release

    if args.release:
        problems = check_release_ready()
        if problems:
            for problem in problems:
                print(f"REFUSE {problem}")
            print("Use --draft for an evaluation package. A release is not authorised.")
            return 1
        if not args.signature or not args.signature.is_file():
            return fail("--release requires --signature over MANIFEST.toml from the release authority")

    print(f"building {version} ({'draft' if draft else 'release'})")
    build = subprocess.run(
        ["cargo", "build", "--release", "--bin", "pos-commercial"],
        cwd=str(CLOSED),
        text=True,
    )
    if build.returncode != 0:
        return fail("cargo build --release")

    name = f"{version}-draft" if draft else version
    stage_root = DIST / "staging"
    stage_dir = stage_root / name
    if stage_dir.exists():
        shutil.rmtree(stage_dir)
    stage_dir.mkdir(parents=True)
    contents = stage(stage_dir, version, draft)

    problems = []
    inspect(stage_dir, contents, problems)
    for path in stage_dir.rglob("*"):
        if path.is_file() and path.suffix.lower() in {".md", ".toml", ".txt", ".json"}:
            text = path.read_bytes()
            if b"private_key_hex" in text or b"BEGIN PRIVATE KEY" in text:
                problems.append(f"key material in package: {path.relative_to(stage_dir)}")
                break
    if problems:
        for problem in problems:
            print(f"FAIL {problem}")
        return 1

    write_manifest(stage_dir, version, draft, release, contents)
    if not draft:
        shutil.copy2(args.signature, stage_dir / "MANIFEST.sig")

    archive = DIST / (f"{name}.tar.gz" if draft else f"{version}.tar.gz")
    make_tarball(stage_dir, archive)
    package_hash = sha256(archive)

    print(f"package: {archive.relative_to(ROOT)}")
    print(f"sha256:  {package_hash}")
    print(f"files:   {len(contents)} plus MANIFEST.toml and SHA256SUMS")
    print("contents: bin/pos-commercial, docs, legal templates, demo data, trust anchor, LICENSE")
    print("source-free: no Rust source, Cargo files, tests, internal ledgers or private keys")
    if draft:
        print("DRAFT: counsel review pending; watermarked and not for partner distribution")
    else:
        print("RELEASE: reviewed templates, signed manifest and provisioned trust anchor")
    return 0


if __name__ == "__main__":
    sys.exit(main())
