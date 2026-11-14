#!/usr/bin/env python3
"""Licence exception register gate (F-01).

Every licence exception must be recorded in `licence-exceptions.toml` with a
named owner, a reason, a scope, and an expiry date. The gate fails when:

  * a required field is missing or empty;
  * an expiry date is in the past (or malformed);
  * a `[[licenses.exceptions]]` crate in deny.toml has no registered exception;
  * a registered exception names a crate that no longer needs one.

Usage:
    python3 scripts/check-licence-exceptions.py [--registry FILE] [--deny FILE]
"""

from __future__ import annotations

import argparse
import datetime as dt
import sys
import tomllib
from pathlib import Path

REQUIRED_FIELDS = ("id", "owner", "reason", "scope", "expires")
MIN_REASON_LENGTH = 20
MIN_SCOPE_LENGTH = 10


def parse_date(value: str) -> dt.date | None:
    try:
        return dt.date.fromisoformat(value)
    except (TypeError, ValueError):
        return None


def registered_crates(entry: dict) -> list[str]:
    crates = entry.get("crates", [])
    if isinstance(crates, str):
        return [crates]
    return [str(crate) for crate in crates]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--registry", default="licence-exceptions.toml")
    parser.add_argument("--deny", default="deny.toml")
    parser.add_argument(
        "--today",
        default=None,
        help="override today's date (YYYY-MM-DD) for deterministic fixtures",
    )
    args = parser.parse_args()

    today = parse_date(args.today) if args.today else dt.date.today()
    if today is None:
        print(f"ERROR: invalid --today value: {args.today}", file=sys.stderr)
        return 2

    registry_path = Path(args.registry)
    if not registry_path.is_file():
        print(f"ERROR: exception register not found: {registry_path}", file=sys.stderr)
        return 2
    try:
        registry = tomllib.loads(registry_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        print(f"ERROR: cannot parse {registry_path}: {exc}", file=sys.stderr)
        return 2

    entries = registry.get("exception", [])
    if not isinstance(entries, list):
        print("ERROR: [[exception]] must be an array of tables", file=sys.stderr)
        return 2

    errors: list[str] = []
    seen_ids: set[str] = set()
    covered_crates: dict[str, str] = {}

    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            errors.append(f"entry #{index}: entry must be a table")
            continue
        label = entry.get("id") or f"entry #{index}"
        for field in REQUIRED_FIELDS:
            value = entry.get(field)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{label}: missing required field '{field}'")
        if not isinstance(entry.get("reason"), str) or len(entry.get("reason", "")) < MIN_REASON_LENGTH:
            errors.append(
                f"{label}: 'reason' must explain the exception in at least "
                f"{MIN_REASON_LENGTH} characters"
            )
        if not isinstance(entry.get("scope"), str) or len(entry.get("scope", "")) < MIN_SCOPE_LENGTH:
            errors.append(
                f"{label}: 'scope' must state where the exception applies in at "
                f"least {MIN_SCOPE_LENGTH} characters"
            )

        identifier = entry.get("id")
        if isinstance(identifier, str):
            if identifier in seen_ids:
                errors.append(f"{label}: duplicate exception id")
            seen_ids.add(identifier)

        expiry = parse_date(entry.get("expires", "")) if isinstance(entry.get("expires"), str) else None
        if expiry is None:
            errors.append(f"{label}: 'expires' must be a YYYY-MM-DD date")
        elif expiry < today:
            errors.append(
                f"{label}: expired on {expiry.isoformat()}; renew with a new reason "
                f"or remove the exception"
            )

        for crate in registered_crates(entry):
            if crate in covered_crates:
                errors.append(
                    f"{label}: crate '{crate}' is already covered by "
                    f"'{covered_crates[crate]}'"
                )
            else:
                covered_crates[crate] = str(identifier)

    deny_path = Path(args.deny)
    if deny_path.is_file():
        try:
            deny = tomllib.loads(deny_path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            print(f"ERROR: cannot parse {deny_path}: {exc}", file=sys.stderr)
            return 2
        deny_crates = {
            exception.get("crate")
            for exception in deny.get("licenses", {}).get("exceptions", [])
            if isinstance(exception, dict) and exception.get("crate")
        }
        for crate in sorted(deny_crates - set(covered_crates)):
            errors.append(
                f"{deny_path}: licences exception for '{crate}' has no entry in "
                f"{registry_path}"
            )
        for crate in sorted(set(covered_crates) - deny_crates):
            errors.append(
                f"{registry_path}: entry '{covered_crates[crate]}' covers '{crate}', "
                f"which has no licences exception in {deny_path}"
            )

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(
            f"\nFAIL: {len(errors)} licence-exception register problem(s). "
            f"See docs/licensing-exceptions.md.",
            file=sys.stderr,
        )
        return 1

    print(
        f"OK: {len(entries)} licence exception(s) are registered with owner, "
        f"reason, scope, and a future expiry."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
