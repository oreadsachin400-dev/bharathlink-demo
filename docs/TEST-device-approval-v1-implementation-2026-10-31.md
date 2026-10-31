# BharathLink V36HF — Trusted Device Approval v1 TEST handover
**31 October 2026 | Implementation completed up to security gate, NOT activated for real devices.**

## Scope and provenance
- Supabase project: `BharathLink-20-TEST` (`fsdusofbpwdrdvgexxyw`) ONLY.
- GitHub feature branch: `bharathlink-device-approval-v1-test`.
- Negative cryptographic tests plus disposable PostgreSQL integration: [GitHub Actions run #41173829825](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41173829825) — **SUCCESS**.
- No merge into main, production/DEMO change, or RLS relaxation.

## Implemented and verified
1. `supabase/functions/bl20-device-approval/approval-crypto.mjs`: strict server-selected, domain-separated payload; P-256 WebCrypto verification; canonical DER signature and base64url validation; no accepting user-supplied approver key.
2. `sql/staged/TEST-device-approval-v1.sql`: two TEST RPCs deployed to the TEST DB, **service_role-only**:
   - `public.bl20_device_approval_context`
   - `public.bl20_commit_device_approval`
   Request row lock, approver status/key checks, exact digest binding, atomic insertion, signer enrollment and one-time consumption. Unknown request, wrong account, missing digest, and replay fail closed.
3. `supabase/functions/bl20-device-approval/index.ts`: deployed as **Edge Function v2** with `verify_jwt=true`; hard-coded `APPROVAL_FEATURE_RELEASED=false`, plus a separate environment flag. It is **not operational for approval**.
4. CI verifies ECDSA signature validity, key substitution and payload tampering, malformed signatures and staging access contracts; a disposable PostgreSQL 17 tests wrong user, first-device denial, altered digest/key, revocation, atomic success and replay.
5. Read-only live TEST checks confirm both RPCs deny `anon` and `authenticated`, admit only `service_role`; no existing RLS policy change.

## Live TEST state after changes
- Active messaging devices: **8**, unchanged.
- Enrollment requests: **0**, unchanged.
- Independently verified signing keys: **0**.
- `messaging_devices_insert_trusted_approval_only`: `WITH CHECK false`, unchanged.
- Existing pairing gate: remains OFF.
- No new device approved or E2EE activation claimed.

## Hard blockers / uncompleted work
1. **Independent first-device bootstrap / audited recovery:** there are no existing verified signing keys or trust anchors; cannot infer trusted status from 8 historical devices.
2. A real signed approval request from an independently verified existing device has not been exercised in the live TEST project.
3. Android secure device-key provisioning, safe UI wiring, server-side trusted-device binding, and E2EE V2 key registration still require implementation and full two-phone tests.
4. Do not set `APPROVAL_FEATURE_RELEASED=true`, turn on pairing, or enable Calls/Messages/Mail from these CI results alone.
5. Before any subsequent rollout, review overall authorization model, Edge/SQL privilege boundary, rate limiting, audit logging, anti-replay concurrency and independent high-assurance recovery design.

**Current verdict: TEST backend approval gate implemented and integration-tested with disposable synthetic data; real enrollment intentionally BLOCKED until independently verified trusted-device bootstrap and end-to-end device tests.**
