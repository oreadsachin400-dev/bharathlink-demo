# BharathLink TEST — E2EE Device Holder Verification (Review Only)

**Security Hold. Not merged or deployed. No existing keys, users, chats or databases changed by this branch.**

## What this branch changes

- Adds a read-only **E2EE Device Security (TEST)** panel under **Profile / Identity details & test tools**. It calls only `bl20_my_e2ee_trust_status()` with the logged-in user's JWT.
- Adds a WebCrypto proof module that verifies control of the **existing non-extractable P-256 ECDH key** and a separately generated **non-extractable ECDSA signing key**.
- Adds an IndexedDB signing-key vault scoped to exact authenticated account + existing device ID.
- Adds the account-scoped, explicitly consented bridge. **It calls `E2EEBackend.getLocal()`, never `activate()`**, so it cannot silently create a replacement device.
- Verifies the challenge's exact account, device, expiry and key pins before sending proof.
- Returns **continuity_proven_not_trusted**, never self-promotes a device to trusted.

## Current release state

- `continuityReleaseEnabled` defaults to **false** in the client.
- Supabase TEST Edge Function `bl20-device-continuity` is separately hard-disabled.
- Supabase TEST `bl20-device-approval` remains hard-disabled.
- Server has **0 independently verified signing keys**. It is unsafe to bootstrap trust from legacy login/identity alone.
- No pending client action can promote a device until an independently reviewed trust-root + recovery process is implemented.

## How to test the safe status UI

Only after independent review and a **TEST-specific deployment**, sign in as an existing TEST account, then open **Profile → Identity details & test tools → E2EE Device Security (TEST)** and select **Refresh device security status**. The panel must show SECURITY HOLD, device counts scoped to that account, and no buttons that register, approve or reset keys.

The review-only branch should **not** be deployed to PROD.

## Unit tests

```sh
node --test security/e2ee-continuity/device-holder-adapter.test.mjs
```

11 local mock tests PASS on 21 November 2026. These are unit tests, **not** actual Android E2EE verification or independent cryptographic audit.

## Mandatory gates before enabling continuity

1. Security review the privileged SQL and Edge Function trust boundary and signer key provenance.
2. Independent identity/provenance verification of each legacy device; recorded explicit physical device-holder consent and recovery plan.
3. Complete existing-vs-new-device UI with unambiguous key safety messages.
4. Two Android phones: consent, valid key possession, wrong account/device, tampered/expired/replayed challenge, revoked device, lost key, second-device read/write and rollback tests.
5. Prove encrypted message, group, media and history remain readable, with no accidental enrollment or plaintext fallback.
6. Only then review enabling the client+Edge gates, first on TEST. Never automatically enable production.

**No Netlify deployment or GitHub PR was triggered by branch creation.**
