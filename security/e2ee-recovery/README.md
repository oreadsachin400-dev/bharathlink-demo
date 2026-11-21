# BharathLink E2EE — Existing-device recovery safety patch

**Branch:** `security/e2ee-existing-device-recovery-20261121`  
**Status:** REVIEW ONLY — NOT DEPLOYED, NO KEY RESTORE CLAIM.

## Why
The original `E2EEBackend.activate()` generated a new local ECDH key and tried to insert directly into `messaging_devices` when the previous local key was absent/inactive. That is unsafe during trusted-device enrollment hold and currently fails database security policy anyway.

## Changed
- Replaced implicit key generation/registration in `activate()` with existing-device-only, fail-closed authorization.
- Added `deviceReadiness()` to distinguish: sign-in missing, local key missing, account mismatch, malformed record, local storage unavailable, server device inactive, server check unavailable, and ready.
- Added **Profile → Identity details & test tools → E2EE Device Recovery (read-only)**. It reports a status only. It does **not** approve, revoke, register, delete, export, reset, rotate, copy, or overwrite encryption keys.
- Added 14 regression tests for the fail-closed behavior; `node --test security/e2ee-recovery/existing-device-recovery.test.mjs`.

## Preservation and restrictions
- The local original ECDH private key remains non-extractable in IndexedDB.
- Missing device key is **not recoverable from login credentials** or encrypted server ciphertext alone.
- Old chats may require their original device, an existing encrypted backup, or a future verified device-to-device history transfer. This patch does not silently generate a replacement.
- Full approval/linking remains disabled because there is no independently trusted signing-key root on the TEST backend.

## Important deployment provenance issue
The user-facing screenshot shows a restricted **BharathLink TEST Home / profile-only preview** page. This page's distinctive text (e.g. `Authenticated TEST Home`) is not present in the tracked `bharathlink-demo` main `index.html`. The separate `BharathLink-Android-Demo` repository README also states the exact latest TEST web source has not been imported. **Do not claim this branch updates that currently deployed preview.**

Before any TEST deployment, obtain and reconcile the *exact source currently deployed to* `bharathlink-20-test.netlify.app` with a verified revision/sha and its separate authentication-state router. Never deploy this branch to PROD or auto-merge.

## Validation
- Read-only test of original server/device registration logic confirms legacy `POST /rest/v1/messaging_devices` path was guarded out.
- Independent local smoke harness with same inspected method implementation: **14/14 PASS**, 0 fail.
- GitHub repository test file also committed; no GitHub CI run claimed yet.
- No Netlify deploy or production database mutation was made.
