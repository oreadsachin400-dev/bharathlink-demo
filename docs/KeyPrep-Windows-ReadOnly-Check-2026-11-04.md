# BharathLink KeyPrep — Windows one-click read-only certificate check

**4 November 2026 | Safety-reviewed local helper | No APK installation**

## One objective

Confirm whether the **already installed** KeyPrep ONLY TEST application on the owner's original Android phone has the same public APK signing certificate as the archived original v40 KeyPrep. This is **not** a device trust or AndroidKeyStore private key test. The original KeyPrep and its data must remain installed.

Expected archival data:
- Package: `com.bharathlink.app.test.keypreponly`
- Version code: `40`
- Public certificate SHA-256: `df835814a04cbf15a1d08e595339d0d9db3fd1b7ba34a1c8ef45c5d422064475`

## Simple Windows laptop flow

1. On **your own trusted Windows laptop**, install Python 3 and the official Google Android SDK **Platform-Tools** and **Build-Tools**, if not already installed. Android Studio SDK Manager provides both. Never install tools from third-party APK download websites. The helper does not download anything.
2. From GitHub, open the exact reviewed branch [bharathlink-keyprep-installed-signer-audit-ci](https://github.com/oreadsachin400-dev/bharathlink-demo/tree/bharathlink-keyprep-installed-signer-audit-ci). Choose **Code → Download ZIP**, unzip into a normal folder on the trusted laptop. Avoid modifying the scripts.
3. Connect **only the original Android phone that already has KeyPrep installed**, using a USB data cable. Enable USB debugging temporarily *only if you choose to authorize the computer for this one-time read-only inspection*. Approve the Android system's USB-debugging authorization dialog only if it shows your own trusted laptop. Do not disable Play Protect or grant elevated privileges.
4. In the unzipped repository folder, double-click **`KeyPrep-Signer-Check-Windows.cmd`**. It detects the SDK from the standard Android Studio path or `ANDROID_HOME`/`ANDROID_SDK_ROOT`, uses Python 3, and invokes only `scripts/audit_installed_keyprep_signer.py`.
5. If the result is `PHONE_APK_CERT_MATCHES_ARCHIVED_KEYPREP_V40`, it means **the phone's installed public APK signing certificate matches the archived v40 certificate**. **It does NOT prove** that anyone has the matching private APK signing key; an app update is still blocked until signing-key custody and Play Protect clearance are independently verified.
6. If output says **`BLOCKED`**, do not uninstall KeyPrep, reset app storage, install another APK, disable Play Protect or export any keys. It can mean missing Android SDK/Python, unapproved USB phone, incorrect package/version, differing signing certificate or a failed local read. Preserve the report's result and stop.
7. Disconnect the USB cable. Turn off USB debugging again (or revoke the temporary computer authorization) when finished.

## Explicit safety guarantee

The helper's allowed operation sequence is **read-only**:
- `adb devices` — identify one authorized device
- `adb shell pm path com.bharathlink.app.test.keypreponly` — locate the installed **public APK**
- `adb pull .../base.apk` — copy public APK to temporary laptop folder
- `apksigner verify --print-certs` — inspect certificate on laptop
- `aapt dump badging` — inspect package/version on laptop
- Delete only the temporary laptop file automatically on completion

No app install, uninstall, data reset, device root, service-role API, OT​​P, private-key export, network upload, keystore interaction or Play Protect bypass.

Windows batch launcher merely discovers local dependencies and starts the Python auditor. It does **not** install SDK/Python or change system-wide PATH or execution-policy settings.

## CI evidence and limitations

- `tests/test_windows_keyprep_launcher.py`: static tests asserting fail-closed dependency handling and no mutating commands.
- `tests/test_installed_keyprep_signer_audit.py`: 11 synthetic safe/unsafe `adb`, `apksigner` and `aapt` cases.
- The Windows GitHub Actions job is intentionally executed on a runner with **no personal authorized USB phone**; it must return BLOCKED/nonzero. That demonstrates absence of false success on an inaccessible phone, **not** a real device test.
- `tests/test_historical_apk_workflow_hold.py`: 6 legacy APK builders and original protected signing workflow held, no debug APK artifact.
- Prior [release-HOLD audit](https://github.com/oreadsachin400-dev/bharathlink-demo/blob/bharathlink-keyprep-installed-signer-audit-ci/docs/Historical-APK-Workflow-Release-HOLD-Audit-2026-11-04.md) remains applicable.

**Status:** tool prepared; phone certificate **NOT YET MEASURED**; signing private-key continuity **UNVERIFIED**; Google Play Protect harmful-app classification **NOT CLEARED**; no Android install or deployment authorized.
