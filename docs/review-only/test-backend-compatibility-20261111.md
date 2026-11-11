# BharathLink-20-TEST — Frontend / official backend compatibility audit
**2026-11-11 | REVIEW ONLY | SECURITY HOLD | NO TEST / PROD DEPLOY**

## What was checked

- GitHub repo: oreadsachin400-dev/bharathlink-demo, main index.html
  (separate from exact *published* Netlify HTML; do not conflate them).
- Official TEST project: fsdusofbpwdrdvgexxyw, public function names and
  authenticated EXECUTE privileges read-only via pg_catalog.
- Static literal RPC calls in the repo's single-file index.html.
- Independent Node tests in this branch, with a strict RELEASE-REFUSAL mode.
- The function inventory is dated, NOT live, and does not inspect real
  account messages, function execution results, JWTs or encryption keys.

## Findings

1. GitHub main index.html configures
   https://lhaiwfdzynssgxmtlytl.supabase.co (old DEMO), NOT official TEST
   https://fsdusofbpwdrdvgexxyw.supabase.co.
2. Static scan: 119 literal RPC call sites, 110 unique RPC names. Of
   those 110 names, only 41 are in the official TEST public-function
   inventory; **69 names are missing**. This counts quoted literal calls
   only; dynamic invocation names and Edge Functions are not included.
3. Public TEST inventory contains 105 distinct function names, of which
   65 have authenticated EXECUTE by name/signature inventory. This is
   **not** functional availability or a full RLS audit.
4. Core 1:1 encrypted send/history/device inventory names are present
   (send_encrypted_message_v2,
   get_my_encrypted_messages_v2_for_conversation,
   get_conversation_messaging_devices,
   is_my_messaging_device_active,
   request_messaging_device_enrollment). Their successful Android use,
   parameter signatures, device trust and E2EE correctness are NOT
   established by function-name presence.
5. The main index.html has no external script src for app.js; a third
   Supabase URL in separate app.js cannot be assumed the active endpoint.
6. The separately published TEST HTML differs from GitHub main; any
   release must reconcile the exact pinned published backup and verify
   its local-session/BLNativeSession compatibility before a deploy.

## Mandatory service gaps

| Workflow | API gap / risk | Required action |
|---|---|---|
| Login / E2EE enrollment | Device request RPC exists but signer bootstrap and approval are security-held | Independent first-device signer audit and no-key-reset two-phone test |
| Normal encrypted chat | Sender/history names exist | Functional session, RLS, send/receive + message retrieval on TEST; don't conclude PASS |
| View Once/disappearing | send_protected_encrypted_message_v2 absent | Remains fail-closed. Draft PR #27 private-vault prototype is NOT live or approved |
| Chat read/unread | mark_conversation_read and mark_conversation_unread absent | Implement exact semantics and RLS or explicitly disable actions; no silent success |
| Verified Directory | search_verified_directory absent | Keep unavailable as an error; no false "fake person" or "not verified" verdict |
| Internal BharathMail | send_bharatmail absent | Keep internal send disabled; NEVER reroute internal mail to external send |
| Profile / status | clear_my_profile_photo, get_my_profile_media, status-story APIs among missing | Feature-by-feature UI/API gate before release |
| Groups | leave_group, make_group_admin, remove_group_member among missing | Verified membership/admin semantics or leave features disabled |

Do NOT blindly replace the DEMO Supabase URL with official TEST. That can
direct production-like user flows at missing RPCs and unknown device keys.

## Auditing and release check

Scripts in this draft:
- scripts/audit-test-backend-compatibility.mjs --audit
  prints read-only JSON, exits 0 even when held (for evidence).
- scripts/audit-test-backend-compatibility.mjs --release
  exits 2 and REFUSES on wrong endpoint, missing referenced RPC name,
  absent mandatory API or missing authenticated EXECUTE. Static success
  alone would NOT prove the app is safe or authorized to deploy.
- tests/test-backend-compatibility-gate.test.mjs
  validates the parser, dated snapshot, known blockers, synthetic
  combinations and actual refusal.
- .github/workflows/test-backend-compatibility-gate.yml
  runs in GitHub without Supabase credentials, write access or Netlify;
  it asserts that the current unsafe release attempt IS REFUSED.

**NOTE:** This draft CI gate is NOT currently in the Netlify deploy process
or Android GitHub build workflow; it must be explicitly approved and wired
into release automation before it can automatically stop those deployments.

CI result: https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/43019878123
11/11 Node tests PASS; source's --release mode REFUSED as required.

## Safe remediation order

1. Keep PROD frozen. Identify exact official TEST published asset and
   source ZIP hash, do not publish backup or inline credentials to public GitHub.
2. Reconcile app/page origin, actual Supabase REST client, Android
   BLNativeSession, 2FA login, non-extractable E2EE IndexedDB keys.
3. Classify each missing literal RPC by reachability: necessary V1,
   intentionally hidden, or obsolete code. When needed, implement backend
   candidate in disposable DB and test parameter signatures, RLS and auth.
4. On a private TEST-compatible source, remove or disable unreachable
   unsafe features *before* enabling official backend. No generic fallbacks.
5. Run two physical Android accounts and device-revocation/restore
   acceptance. Only then consider an explicitly approved TEST deployment.
6. Leave PROD unchanged until signed APK, call, notification, mail and
   E2EE release gates pass.

Draft audit contains public function names and frontend paths only, NO
user data, backup ZIP, session tokens, passwords, signed keys or secrets.
