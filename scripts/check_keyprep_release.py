#!/usr/bin/env python3
"""Strict pre-distribution check for an existing KeyPrep ONLY TEST in-place update.

Checks the actual, apksigner-verified certificate report AND the Android aapt
manifest report. This does not establish phone-side installed signature.

No signing private key is stored here.
"""
from pathlib import Path
import re
import sys
from check_keyprep_signing import check_report

EXPECTED_PACKAGE = "com.bharathlink.app.test.keypreponly"
# Version 40 is the installed original KeyPrep-only app. Only an update > 40
# should be offered; never downgrade or reinstall.
MINIMUM_UPDATE_CODE = 41

PACKAGE_LINE = re.compile(r"^package:\s+(.+)$", re.M)
NAME = re.compile(r"(?:^|\s)name='([^']*)'")
VERSION = re.compile(r"(?:^|\s)versionCode='([^']*)'")

def check_release(signing_report: str, badging_report: str):
    good, message = check_report(signing_report)
    if not good:
        return False, message
    match = PACKAGE_LINE.findall(badging_report)
    if len(match) != 1:
        return False, "BLOCKED: absent or ambiguous Android package declaration"
    name = NAME.findall(match[0])
    code = VERSION.findall(match[0])
    if len(name) != 1 or name[0] != EXPECTED_PACKAGE:
        return False, "BLOCKED: incorrect or missing KeyPrep application ID"
    if len(code) != 1 or not re.fullmatch(r"[1-9][0-9]{0,8}", code[0]):
        return False, "BLOCKED: missing, negative, or malformed Android version code"
    if int(code[0]) < MINIMUM_UPDATE_CODE:
        return False, "BLOCKED: version code is not newer than original KeyPrep-only build"
    return True, "ARCHIVED_CERT_AND_PACKAGE_MATCH: physical phone identity still unverified"

def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: check_keyprep_release.py <apksigner-report> <aapt-badging-report>")
    results = []
    for path in sys.argv[1:]:
        file = Path(path)
        if not file.is_file() or file.stat().st_size > 65536:
            raise SystemExit("BLOCKED: missing or oversized APK metadata")
        results.append(file.read_text(encoding="utf-8", errors="replace"))
    ok, message = check_release(*results)
    print(message)
    raise SystemExit(0 if ok else 1)

if __name__ == "__main__":
    main()
