# Protected Android/WebView inbox integration contract — REVIEW ONLY

**11 November 2026 | SECURITY HOLD | no deploy / no live Supabase writes**

Code: review-only/protected-inbox-controller.mjs
Tests: tests/protected-inbox-controller.test.mjs
Isolated CI: https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/43017039411

## What was implemented

An isolated JavaScript ES-module controller (NOT imported by index.html or
app.js) supports the protected inbox and View Once claim RPC contracts
against injected dependencies. It contains no network implementation,
tokens, direct SQL, persistent storage, timers, background jobs or
key-persistence code.

- list_my_protected_messages_v1: server returns a key-free original reader
  index and possibly encrypted body. The controller exposes only ID,
  state and date to the UI, not the encrypted body or device keys.
- claim_protected_wrapped_key_v1: ONLY after explicit synchronous
  confirmation from a real UI button click. E2EE-wrapped material goes
  directly to an injected trusted on-device decrypt adapter, not to list UI.

Strict origin/project gate: expected
https://bharathlink-20-test.netlify.app plus official TEST Supabase project
fsdusofbpwdrdvgexxyw. The actual published TEST HTML still points to
old DEMO Supabase lhaiwfdzynssgxmtlytl. This controller cannot be
connected to that source; keep it review-only.

## Required host wiring (not implemented/released)

1. getOrigin must read actual runtime origin, never an unchecked input.
2. getSupabaseProject must derive from the actual authenticated client
   endpoint, not a separate spoofable flag.
3. getContext must read the authenticated account, current device and chat,
   plus a session epoch changed on login, logout or account switch.
   A verifiedSigner:true client value is only a fail-closed UX hint.
   The server MUST independently enforce signer verification, ownership,
   membership and active device for every RPC.
4. rpc uses a normal authenticated Supabase session, never service_role
   keys or copied JWTs. Disable automatic retry of one-time claims and
   never log wrapped keys, tokens or response bodies.
5. decryptWithCurrentDevice uses existing nonextractable E2EE device key.
   The controller does not generate, enroll, reset, export or clone keys.
6. Navigation loads only key-free metadata. A real Open Once button click
   invokes openOnce with a synchronous confirmation callback.
   NEVER invoke it from page render, lifecycle hook, notification,
   Realtime subscription or background worker.
7. Account switch clears cached old inbox. In-flight old-account response
   cannot decrypt or restore old metadata into new-account cache.
8. The prototype opens View Once only; TTL and media need their own UX.

## Response-loss limitation

Server consumes View Once when the claim transaction commits, not when
Android receives or decrypts it. If HTTP response or decrypt fails,
the controller returns consumption_unknown with a no-retry barrier.
Even on stale inbox refresh it does not present Open again. This
preserves single-use semantics but can permanently lose a message
despite the user never seeing it. Production requires an independently
audited ACK/recovery design without unlimited retries.

## Evidence and limits

- 17/17 Node controller tests pass.
- Disposable PostgreSQL 16 vault-only sender, recipient index,
  first-claim-wins, expiry and real 2-session row-lock concurrency pass.
- Actual TEST signing-key columns and check constraints verified read-only.
  The fixture now requires EC P-256 x/y 43-character encodings and correct
  verification methods, but synthetic test points are NOT valid
  cryptographic proof or attested first-device enrollment.
- No actual Android signed APK, WebView local key, live authenticated
  session, rendered click wiring or two-physical-phone tests passed here.
- TEST origin/backend source mismatch remains.
- SQL RPC client EXECUTE permissions remain REVOKED in review candidate;
  temporary grants exist ONLY in a disposable PostgreSQL CI service.

## Release gates

Reconcile exact deployed source and official TEST backend, signer bootstrap,
all Data API and RLS read paths, Realtime, backup, protected media and
storage, claim response-loss recovery and Android two-phone tests.
Do not merge PR #27, deploy, enable RPC permissions, re-enroll devices
or reset existing E2EE keys based on this isolated CI result.
