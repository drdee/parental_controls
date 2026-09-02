#!/usr/bin/env python3
"""Check a .mobileconfig against Apple's official device-management schemas.

Two payloads in this project had to be removed after they failed the *entire*
profile install on a Mac without MDM — first `ProhibitDisablement`, then the
whole `com.apple.webcontent-filter` payload. Both were avoidable: Apple
publishes machine-readable schemas at github.com/apple/device-management that
say plainly which keys macOS supports.

A key marked `introduced: n/a` for macOS, or declared only under `iOS`, does
not degrade gracefully — it takes the whole profile down with one opaque
"CPDomainPlugin" error.

Usage:
    tools/lint-profile.py <profile.mobileconfig> [--schemas <dir>] [--os macOS]

Exit status is non-zero if any error-level problem is found.
"""
from __future__ import annotations

import argparse
import pathlib
import plistlib
import re
import subprocess
import sys

SCHEMA_REPO = "https://github.com/apple/device-management"

# Keys absent from Apple's public schema that were nonetheless confirmed to
# work: each appears in ManagedClient's own string table and in a live
# MDM-delivered profile on a real Mac. Anything not on this list is treated as
# an error, because an undocumented key can fail the whole install.
UNDOCUMENTED_BUT_VERIFIED = {
    # Both appear in ManagedClient's string table and in a live MDM-delivered
    # profile on a real Mac. com.apple.MCX has no published schema at all.
    "forceInternetSharingOff",
    "DisableGuestAccount",
}
DEFAULT_SCHEMA_DIR = pathlib.Path("/tmp/appledm")


class Finding:
    def __init__(self, level: str, payload: str, message: str) -> None:
        self.level = level
        self.payload = payload
        self.message = message

    def __str__(self) -> str:
        return f"{self.level:7} {self.payload}: {self.message}"


def ensure_schemas(directory: pathlib.Path) -> pathlib.Path:
    """Clone Apple's schema repository if it is not already present."""
    if (directory / "mdm" / "profiles").is_dir():
        return directory
    print(f"fetching schemas into {directory} ...", file=sys.stderr)
    subprocess.run(
        ["git", "clone", "--depth", "1", SCHEMA_REPO, str(directory)],
        check=True,
        capture_output=True,
    )
    return directory


def key_blocks(yaml_text: str) -> dict[str, str]:
    """Maps each `- key: Name` to its YAML block."""
    blocks: dict[str, str] = {}
    for match in re.finditer(
        r"^\s*-\s*key:\s*(\S+)[ \t]*\n(.*?)(?=^\s*-\s*key:|\Z)", yaml_text, re.S | re.M
    ):
        blocks[match.group(1)] = match.group(2)
    return blocks


class Support:
    """What a schema says about one key on one platform."""

    def __init__(self, introduced: str, allows_manual_install: bool,
                 supervised: bool = False) -> None:
        self.introduced = introduced
        self.allows_manual_install = allows_manual_install
        self.supervised = supervised

    @property
    def never_supported(self) -> bool:
        return self.introduced == "n/a"


def supported_platforms(block: str) -> dict[str, Support]:
    """Platform -> support facts, from a key's `supportedOS` block.

    Two fields matter here and both have bitten this project:

    - `introduced: n/a` means the key exists in the schema but the platform
      never supported it.
    - `allowmanualinstall: false` means the key only takes effect when the
      profile arrives over MDM. A manually installed profile containing it
      fails to install at all.
    """
    section = re.search(r"supportedOS:\s*\n(.*?)(?=^\s{2}\w|\Z)", block, re.S | re.M)
    if not section:
        return {}
    platforms: dict[str, Support] = {}
    for entry in re.finditer(
        r"^\s{4}(\w+):[ \t]*\n((?:[ \t]{6,}.*\n)*)", section.group(1), re.M
    ):
        body = entry.group(2)
        introduced = re.search(r"introduced:\s*'?([^'\n]+)", body)
        manual = re.search(r"allowmanualinstall:\s*(\w+)", body)
        supervised = re.search(r"supervised:\s*(\w+)", body)
        platforms[entry.group(1)] = Support(
            introduced=introduced.group(1).strip() if introduced else "?",
            allows_manual_install=(manual.group(1) != "false") if manual else True,
            supervised=(supervised.group(1) == "true") if supervised else False,
        )
    return platforms


def lint(profile_path: pathlib.Path, schema_dir: pathlib.Path, target_os: str) -> list[Finding]:
    findings: list[Finding] = []
    with profile_path.open("rb") as handle:
        profile = plistlib.load(handle)

    # Structural checks that do not need a schema.
    if profile.get("PayloadType") != "Configuration":
        findings.append(Finding("error", "<root>", "PayloadType must be 'Configuration'"))
    if profile.get("PayloadScope") != "System":
        findings.append(
            Finding(
                "error",
                "<root>",
                "PayloadScope should be 'System'; the DNS and content-filter "
                "handlers reject user-scoped profiles outright",
            )
        )
    payloads = profile.get("PayloadContent", [])
    uuids = [p.get("PayloadUUID") for p in payloads]
    if len(set(uuids)) != len(uuids):
        findings.append(Finding("error", "<root>", "duplicate PayloadUUID"))
    identifiers = [p.get("PayloadIdentifier") for p in payloads]
    if len(set(identifiers)) != len(identifiers):
        findings.append(Finding("error", "<root>", "duplicate PayloadIdentifier"))

    profiles_dir = schema_dir / "mdm" / "profiles"

    for payload in payloads:
        payload_type = payload.get("PayloadType", "<missing>")
        schema_file = profiles_dir / f"{payload_type}.yaml"

        if not schema_file.exists():
            # Third-party domains (Chrome, Firefox) have no Apple schema; that
            # is expected and not a problem.
            if payload_type.startswith("com.apple."):
                findings.append(
                    Finding("warning", payload_type, "no Apple schema found for this payload")
                )
            continue

        schema_text = schema_file.read_text()

        # Check the payload itself before its keys: a payload that macOS does
        # not support, or that requires MDM delivery, fails the whole install
        # regardless of which keys it carries.
        head = schema_text.split("payloadkeys:")[0]
        payload_platforms = supported_platforms(head)
        if payload_platforms:
            payload_support = payload_platforms.get(target_os)
            if payload_support is None:
                findings.append(
                    Finding(
                        "error",
                        payload_type,
                        f"this payload is not supported on {target_os} "
                        f"(declared for: {', '.join(sorted(payload_platforms))})",
                    )
                )
                continue
            if payload_support.never_supported:
                findings.append(
                    Finding("error", payload_type,
                            f"this payload is marked 'introduced: n/a' for {target_os}")
                )
                continue
            if not payload_support.allows_manual_install:
                findings.append(
                    Finding("error", payload_type,
                            "this payload has 'allowmanualinstall: false' — it requires "
                            "MDM delivery and cannot be installed by hand")
                )
                continue
            if payload_support.supervised:
                findings.append(
                    Finding("warning", payload_type,
                            "this payload is marked 'supervised: true'; it may be ignored "
                            "on a Mac that is not supervised")
                )

        blocks = key_blocks(schema_text)

        for key in payload:
            if key.startswith("Payload"):
                continue
            block = blocks.get(key)
            if block is None:
                # An unknown key inside an Apple payload is an error, not a
                # warning. `ProhibitDisablement` is absent from the schema
                # entirely and still failed the whole install, so "not
                # documented" cannot be treated as "probably fine".
                #
                # Keys verified to work despite being undocumented are listed
                # in UNDOCUMENTED_BUT_VERIFIED below.
                level = "warning" if key in UNDOCUMENTED_BUT_VERIFIED else "error"
                detail = (
                    "not in Apple's schema, but verified working on a real machine"
                    if level == "warning"
                    else "is not in Apple's schema for this payload — an undocumented "
                         "key can fail the entire install"
                )
                findings.append(Finding(level, payload_type, f"{key} {detail}"))
                continue

            platforms = supported_platforms(block)
            if not platforms:
                continue

            support = platforms.get(target_os)
            if support is None:
                others = ", ".join(sorted(platforms)) or "none"
                findings.append(
                    Finding(
                        "error",
                        payload_type,
                        f"{key} is not supported on {target_os} (declared for: {others})",
                    )
                )
                continue

            if support.never_supported:
                findings.append(
                    Finding(
                        "error",
                        payload_type,
                        f"{key} is marked 'introduced: n/a' for {target_os} — "
                        "in the schema but never supported",
                    )
                )
            elif support.supervised:
                findings.append(
                    Finding(
                        "warning",
                        payload_type,
                        f"{key} is marked 'supervised: true' — likely ignored on an "
                        "unsupervised Mac (harmless, but it does nothing)",
                    )
                )
            elif not support.allows_manual_install:
                findings.append(
                    Finding(
                        "error",
                        payload_type,
                        f"{key} has 'allowmanualinstall: false' — it requires MDM "
                        "delivery, and its presence fails a manual install",
                    )
                )

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", type=pathlib.Path)
    parser.add_argument("--schemas", type=pathlib.Path, default=DEFAULT_SCHEMA_DIR)
    parser.add_argument("--os", dest="target_os", default="macOS")
    args = parser.parse_args()

    if not args.profile.exists():
        print(f"error: no such file: {args.profile}", file=sys.stderr)
        return 2

    schema_dir = ensure_schemas(args.schemas)
    findings = lint(args.profile, schema_dir, args.target_os)

    errors = [f for f in findings if f.level == "error"]
    warnings = [f for f in findings if f.level == "warning"]

    for finding in errors + warnings:
        print(finding)

    print()
    print(f"{args.profile.name}: {len(errors)} error(s), {len(warnings)} warning(s)")
    if errors:
        print()
        print("An unsupported key does not get ignored — it fails the whole")
        print("profile install with an opaque CPDomainPlugin error.")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
