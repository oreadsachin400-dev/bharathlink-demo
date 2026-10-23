# V39 trusted-device approval: TEST cutover runbook (SECURITY HOLD)

Status: DESIGN / REVIEW ONLY. No hosted SQL, RPC permission, Android build or Netlify deployment is authorized by this file.

## Hard incompatibility
- Existing `public.register_e2ee_v2_device(uuid,text,text)` is executable by authenticated clients and does not verify a signed approval. A new approval endpoint **alone** does not close this bypass.
- Existing V2 signing keys are raw Ed25519 (or diagnostic P-256) and **must not** be silently reinterpreted as verified P-256 approver anchors.
- Existing `public.messaging_device_enrollment_requests` stores candidate P-256 JWKs but does not supply the canonical V39 request, approver ID, nonce digest and immutable receipt as a verified authority.
- Android launcher loads TEST Netlify WebView. Native Android source is not proof of deployed web behavior.

## Required implementation order
1. **Inventory without mutation:** capture deployed TEST asset fingerprint, all registration paths and authenticated RPC grants; record callers and test-device state. Never read private E2EE keys.
2. **Establish approver authority:** trusted server must verify independent initial enrollment / recovery authority; only after that may it register a verified, non-revoked signing anchor. Existing unverified anchors cannot be promoted by metadata flags.
3. **Bind a candidate request:** server generates unpredictable nonce, one-time request ID, expiry <=10 minutes; bind account ID, candidate device ID, candidate encryption + signing keys, trusted approver ID and SHA-256 digests. No client-controlled `verified` flag.
4. **Verify in one serializable transaction:** authenticate account from verified JWT; lock request and verified approver anchor; compare exact account/device/key digests; verify P-256 SHA-256 signature over canonical transcript; insert device and immutable receipt; consume request; rollback everything on any error. Prevent concurrent replay.
5. **Close all bypasses atomically with release:** deny the legacy V2 registration RPC to authenticated clients and audit direct table insert, other SECURITY DEFINER RPCs, service-role endpoints and old client versions. Do not revoke the RPC before a backward-compatibility and recovery plan is verified.
6. **Test on disposable DB first:** unauthenticated/cross-account/self/revoked/expired/replay/concurrent duplicate/receipt-failure/key-swap/first-device/recovery. Then TEST backend migration with a rollback plan and two-phone Android tests.
7. **Release only after go/no-go:** TEST approval and key continuity proven; production never modified by this work.

## Explicit release blockers
- No verified initial-device or lost-device recovery authority.
- No production-ready trusted server endpoint wired to TEST.
- No exhaustive deployed TEST caller inventory or safe legacy RPC cutover.
- No Android two-phone validation of the signed flow.

## Safe current action
Keep V39 references non-deployed and legacy diagnostic registration fail-closed in the inspected GitHub web branch. Keep hosted TEST RPC unchanged until the complete cutover is ready. Never claim CI PASS means live approval is secure.
