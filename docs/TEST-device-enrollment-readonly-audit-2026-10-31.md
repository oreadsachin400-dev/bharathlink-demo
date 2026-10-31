# BharathLink TEST device enrollment — read-only audit (31 October 2026)

Scope: **BharathLink-20-TEST** only. GitHub TEST branch: `bharathlink-v36hf-kotlin-test`.

## Confirmed evidence

- Physical Android DIAG TEST: APK installed; TEST login and profile displayed.
- Device check displays **local E2EE key unavailable** and account onboarding **not confirmed**.
- Note: DIAG TEST has its own Android package and isolated WebView storage; a missing local browser key in this installation does **not** establish that another installation has lost its keys.
- TEST DB: `messaging_devices` RLS enabled, authenticated INSERT policy is fail-closed (`WITH CHECK false`).
- TEST DB: 8 active messaging devices and 0 enrollment requests at audit time.
- Enrollment request, challenge, pending/status, and cancel functions exist.
- No trusted-device approval/bootstrap RPC identified in the inspected TEST database function catalog.
- The existing `register_e2ee_v2_device` function has a separate registration purpose. **E2EE-v2 registration is not proof of trusted-device approval**.
- TEST `bl20-pairing-gate` v3: `pairingEnabled=false`, `registrationEnabled=false`; GET-only.
- No TEST database tables, functions, RLS policies, existing device keys, or edge functions were changed as part of this audit.

## Next engineering gate (remain disabled)

1. Independently verify account-linking/bootstrap policy without trusting a login alone.
2. Design server-side, one-time, expiry-bound challenge approval for a previously trusted device and restrict signing proof to the server's registered approver key.
3. Implement atomic authorization, replay prevention, audit logging, ownership checks, revocation checks and fail-closed response.
4. Verify newly approved device bindings and local keys separately from E2EE-v2 registration. Never export or migrate private keys casually across Android package data directories.
5. Run negative-path tests: wrong user, key substitution, expired challenge, replay, revoked approver, duplicate ID, concurrency and first-device bootstrap lacking independent proof.
6. Run actual two-phone E2EE send/decrypt only after documented authorization passes.
7. Keep production and DEMO unchanged, and do not enable the communication preview before those gates.

Status: **READ-ONLY AUDIT RECORDED; TRUST APPROVAL NOT IMPLEMENTED; NO LIVE ENROLLMENT ENABLED.**
