#!/usr/bin/env python3
"""Read-only ADB audit of the INSTALLED KeyPrep ONLY TEST APK signing certificate.

Compares installed APK certificate with archived GitHub APK certificate.
No new APK is built, installed, signed, updated, or published; no Android data,
private keys, OTPs or account information are accessed. The sole adb data read
is pm path plus the public installed app's own base.apk, copied into a
temporary directory and removed before return. No root or run-as.

Requirements: Android SDK platform-tools adb, build-tools apksigner and aapt;
one USB-authorized Android device. Intended for local opt-in use on a trusted
laptop after the user connects their own device. Not remotely executable by CI.
"""
import json
import re
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Callable, Sequence

from check_keyprep_signing import (
    INSTALLED_CANDIDATE_CERT_SHA256,
    check_report,
)

PKG = "com.bharathlink.app.test.keypreponly"
EXPECTED_ORIGINAL_VERSION_CODE = 40
BASE_APK_PATH = re.compile(r"^/data/app/[A-Za-z0-9_~+./=\-]+/base\.apk$")
VERSION = re.compile(
    r"^package:\s+name='([^']+)' versionCode='([0-9]+)'(?:\s|$)",
    re.MULTILINE,
)


class AuditBlocked(Exception):
    pass


def parse_devices(report: str) -> str:
    """Require exactly one Android device with authorized adb state."""
    rows = [x.strip() for x in report.splitlines()
            if x.strip() and not x.startswith("List of devices attached")
            and not x.startswith("*")]
    devices = []
    for row in rows:
        fields = row.split()
        if len(fields) < 2:
            continue
        serial, state = fields[:2]
        if state == "device":
            if not re.fullmatch(r"[A-Za-z0-9_.:\-]+", serial):
                raise AuditBlocked("unexpected ADB device identifier")
            devices.append(serial)
        elif state in ("offline", "unauthorized", "recovery", "sideload"):
            raise AuditBlocked("Android device not authorized for read-only ADB inspection")
    if len(devices) != 1:
        raise AuditBlocked("connect exactly one authorized Android phone over USB")
    return devices[0]


def parse_installed_base_path(report: str) -> str:
    paths = [
        line[len("package:"):]
        for line in report.splitlines()
        if line.startswith("package:")
    ]
    bases = [p for p in paths if p.endswith("/base.apk")]
    if len(bases) != 1:
        raise AuditBlocked("cannot identify one installed KeyPrep base.apk")
    p = bases[0]
    if not BASE_APK_PATH.fullmatch(p) or ".." in p or "//" in p:
        raise AuditBlocked("unsafe or unexpected package path; refuse adb pull")
    return p


def parse_installed_badging(report: str) -> int:
    m = VERSION.findall(report)
    if len(m) != 1 or m[0][0] != PKG:
        raise AuditBlocked("package identity differs from preserved KeyPrep ONLY TEST app")
    code = int(m[0][1])
    if code != EXPECTED_ORIGINAL_VERSION_CODE:
        raise AuditBlocked("installed KeyPrep version is not the archived v40: manual review required")
    return code


def safe_run(args: Sequence[str], timeout_seconds: int) -> str:
    """argv only: no shell commands, shell expansions, or networking."""
    try:
        result = subprocess.run(
            list(args), check=True, capture_output=True,
            text=True, timeout=timeout_seconds,
        )
        return result.stdout
    except (FileNotFoundError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as e:
        raise AuditBlocked("required local Android inspection command failed") from e


def audit(
    adb: str = "adb",
    apksigner: str = "apksigner",
    aapt: str = "aapt",
    runner: Callable[[Sequence[str], int], str] = safe_run,
) -> dict:
    serial = parse_devices(runner([adb, "devices"], 12))
    # The approved operation list is deliberately small and read-only.
    p = parse_installed_base_path(
        runner([adb, "-s", serial, "shell", "pm", "path", PKG], 12)
    )
    with TemporaryDirectory(prefix="bharathlink_keyprep_readonly_") as temp:
        apk = Path(temp) / "installed-base.apk"
        runner([adb, "-s", serial, "pull", p, str(apk)], 25)
        if not apk.is_file() or not (512 <= apk.stat().st_size <= 250_000_000):
            raise AuditBlocked("unable to securely read installed public APK")
        signed = runner([apksigner, "verify", "--verbose", "--print-certs", str(apk)], 25)
        match, reason = check_report(signed)
        if not match:
            raise AuditBlocked(
                "installed signer does not match archived KeyPrep signing identity"
            )
        badging = runner([aapt, "dump", "badging", str(apk)], 25)
        version = parse_installed_badging(badging)
    return {
        "verdict": "PHONE_APK_CERT_MATCHES_ARCHIVED_KEYPREP_V40",
        "package": PKG,
        "installed_version_code": version,
        "installed_certificate_sha256": INSTALLED_CANDIDATE_CERT_SHA256,
        "archived_certificate_sha256": INSTALLED_CANDIDATE_CERT_SHA256,
        "original_private_signing_key_verified_available": False,
        "safe_update_authorized": False,
        "play_protect_clearance_verified": False,
        "trusted_device_approved": False,
        "no_install_or_private_key_operation": True,
        "local_apk_copy_deleted": True,
        "notice": (
            "Only the publicly installed APK certificate was inspected. "
            "A matching certificate does not establish possession of the "
            "original private signing key, Google Play Protect approval, "
            "or permission to deploy an update."
        ),
    }


def main() -> int:
    if len(sys.argv) != 1:
        print("Usage: python3 scripts/audit_installed_keyprep_signer.py", file=sys.stderr)
        return 2
    try:
        print(json.dumps(audit(), indent=2, sort_keys=True))
        return 0
    except AuditBlocked as exc:
        print("BLOCKED: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
