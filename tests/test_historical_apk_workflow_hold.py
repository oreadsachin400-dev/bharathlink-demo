"""Play Protect HOLD for archived APK producing GitHub Actions workflows.

This test DOES NOT approve APKs, change GitHub actions settings, or
authoritatively attest all historical forks/branches. It validates the
current reviewed branch and the six known legacy workflows where debug
APK artifacts could have been published.
"""
import json
import re
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
WF=ROOT/".github"/"workflows"

KNOWN_APK_PRODUCERS={
    "build-android-test.yml": "build",
    "build-v36hf-kotlin-test.yml": "kotlin-v36hf-test",
    "build-v36hf-keyprep-test.yml": "keyprep-test",
    "build-phase6-offline-freshprep.yml": "fresh-offline-android",
    "build-signing-inspector.yml": "offline-inspector",
    "phase6-offline-freshprep-android.yml": "isolated-native-selftest",
    "keyprep-protected-signing.yml": "sign-existing-keyprep",
}
PREVIOUS_DEBUG_WORKFLOWS={
    "build-isolated-auth-probe-test.yml",
    "phase7a-isolated-auth-binding-android.yml",
}

def jobs(source):
    # Identify exact two-space-indented YAML job headings below 'jobs:'.
    if "\njobs:\n" not in "\n"+source:
        return {}
    body=("\n"+source).split("\njobs:\n",1)[1]
    positions=list(re.finditer(r"(?m)^  ([A-Za-z0-9_-]+):\s*$",body))
    return {m.group(1):body[m.end():positions[i+1].start() if i+1<len(positions) else len(body)]
            for i,m in enumerate(positions)}

def held(job_body):
    return bool(re.search(r"(?m)^    if:\s*false\s*$",job_body))

def apks_uploaded(job_body):
    # A real GitHub upload-artifact ACTION, not string mentions in guard shell.
    steps=list(re.finditer(r"(?m)^      - uses:\s*actions/upload-artifact@v\d+",job_body))
    for index,m in enumerate(steps):
        # Limit analysis to this action's YAML step (next 6-space step or job end).
        next_step=re.search(r"(?m)^      - (?:name:|uses:)",job_body[m.end():])
        end=m.end()+next_step.start() if next_step else len(job_body)
        action=job_body[m.start():end]
        if re.search(r"(?i)(?:\.apk\b|/outputs/apk|app-debug\.apk)",action):
            return True
    return False

class HistoricalDebugApkHoldTests(unittest.TestCase):
    def test_every_known_old_apk_publishing_job_is_explicitly_disabled(self):
        for file,job in KNOWN_APK_PRODUCERS.items():
            src=(WF/file).read_text(encoding="utf8")
            pieces=jobs(src)
            with self.subTest(workflow=file):
                self.assertIn(job,pieces)
                self.assertTrue(held(pieces[job]),
                    "BLOCK: old APK producer job is not held")
                self.assertIn("Play Protect",src)

    def test_no_active_job_uploads_an_installable_apk(self):
        for file in sorted(WF.glob("*.yml")):
            src=file.read_text(encoding="utf8")
            for name,body in jobs(src).items():
                if apks_uploaded(body):
                    with self.subTest(file=file.name,job=name):
                        self.assertTrue(held(body),
                            "BLOCK: active GitHub job can publish an APK artifact")

    def test_phase7a_and_auth_probe_are_compilation_only(self):
        for name in PREVIOUS_DEBUG_WORKFLOWS:
            s=(WF/name).read_text(encoding="utf8")
            with self.subTest(name=name):
                self.assertIn(":app:testDebugUnitTest",s)
                self.assertNotIn(":app:assembleDebug",s)
                self.assertNotRegex(s,r"(?m)^\s+- uses:\s*actions/upload-artifact@")
                self.assertIn("test ! -d v36hf-kotlin-build/app/build/outputs/apk",s)

    def test_protected_signing_keystore_not_removed_but_job_held(self):
        w=(WF/"keyprep-protected-signing.yml").read_text(encoding="utf8")
        self.assertTrue(held(jobs(w)["sign-existing-keyprep"]))
        self.assertIn("name: keyprep-signing",w)
        self.assertIn("BHARATHLINK_KEYPREP_KEYSTORE_B64",w)
        self.assertIn("python3 scripts/check_keyprep_release.py",w)
        self.assertNotIn("if: true",w)

    def test_release_readiness_still_holds_without_claiming_clearance(self):
        metadata=json.loads((ROOT/"docs/security-release-readiness.json").read_text())
        self.assertEqual(metadata["release_decision"],"HOLD")
        self.assertEqual(metadata["signing_provenance"]
                         ["real_installed_certificate_status"],"NOT_YET_READ_FROM_PHONE")
        self.assertFalse(metadata["is_test_apk_install_approved"])
        self.assertFalse(metadata["is_production_authorized"])

if __name__=="__main__":
    unittest.main()
