#!/usr/bin/env python3
"""Fail-closed Android signing certificate preflight for BharathLink KeyPrep TEST.

Compares a verified SHA-256 certificate fingerprint from apksigner --print-certs
to the certificate observed in the previously installed KeyPrep ONLY TEST
GitHub APK artifact. No keys, passwords or sensitive user identifiers involved.

Usage:
  python3 scripts/check_keyprep_signing.py apk-signing.txt

Absence, ambiguity and mismatch are blocking errors. Passing this test only
establishes certificate continuity with the archived artifact, *not* that the
phone's currently installed package has been independently attested.
"""
import re
import sys
from pathlib import Path

INSTALLED_CANDIDATE_CERT_SHA256 = (
    "df835814a04cbf15a1d08e595339d0d9db3fd1b7ba34a1c8ef45c5d422064475"
)
PATTERN = re.compile(r"^Signer #1 certificate SHA-256 digest:\s*([a-fA-F0-9]{64})\s*$", re.M)
OTHER = re.compile(r"^Signer #\d+ certificate SHA-256 digest:", re.M)


def check_report(report: str):
    matches = PATTERN.findall(report)
    signers = OTHER.findall(report)
    if len(matches) != 1 or len(signers) != 1:
        return False, "BLOCKED: certificate report missing, ambiguous or multi-signer"
    fingerprint = matches[0].lower()
    if fingerprint != INSTALLED_CANDIDATE_CERT_SHA256:
        return False, "BLOCKED: certificate does not match previously delivered KeyPrep ONLY TEST"
    return True, "CERTIFICATE_MATCHES_ARCHIVED_APK: additional device-side checks still required"


def main():
    if len(sys.argv) != 2:
        raise SystemExit("Usage: check_keyprep_signing.py <apksigner-report>")
    p = Path(sys.argv[1])
    if not p.is_file() or p.stat().st_size > 65536:
        raise SystemExit("BLOCKED: missing or oversized signing report")
    good, message = check_report(p.read_text(encoding="utf-8", errors="replace"))
    print(message)
    raise SystemExit(0 if good else 1)


if __name__ == "__main__":
    main()
