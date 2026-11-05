# BharatMail TEST — Automatic received attachment metadata snapshot

Date: 5 November 2026. Scope: **newly received signed Resend emails only**, metadata-only, best effort, TEST infrastructure.

## What changed

The existing live signed inbound webhook `bharatmail-inbound-webhook` was upgraded from **v8** to **v9** with an additive post-routing step. The original HMAC/Svix header validation, strict 5-minute timestamp check, inbound-event persistence, message-detail retrieval, inbound event update, `bharatmail_route_inbound_event` RPC call, error returns, and successful HTTP 200 response **remain byte-for-byte equivalent** to v8 outside the appended metadata call and its module import.

After `route.ok` and `route.json()`:

1. Re-query recipient-linked **inbound** external message rows by server-known Resend provider email ID (service-role access only). Reject unlinked, malformed, duplicate and more-than-30-recipient rows.
2. Call the fixed Resend Receiving Attachments **list metadata** endpoint with the server-only Resend key. No download URL is followed.
3. Require complete provider list (`has_more=false`), at most 20 nonempty items, valid filename/content type/size, and JSON under 29 KiB.
4. Build only `{filename,content_type,size_bytes}` for each attachment; no attachment provider ID, download URL, storage path, file bytes, message body, sender address, or link is copied into the snapshot.
5. Insert owner-bound `bharatmail_received_attachment_snapshots` rows using `on_conflict=external_message_id` + `resolution=ignore-duplicates`; never overwrite earlier user-triggered snapshots.
6. Confirm every inserted-or-existing row by readback of message ID, owner, item count and provenance. Status-only server logs contain no user email, filename, provider ID or token.

The post-routing stage uses a shared 6.5-second timeout and catches all errors. Any automatic metadata failure **does not turn a successfully routed email into a failed delivery**, and does not imply file safety or successful persistence. Missing/empty/partial provider lists are not saved as complete snapshots.

## Exact deployment

- Project: `fsdusofbpwdrdvgexxyw` (TEST).
- Live edge: `bharatmail-inbound-webhook` version **9**, `verify_jwt=false` only because the handler independently authenticates Resend's signed webhook.
- Backup of the previously deployed v8 code: `docs/archive/BharatMail-Inbound-Webhook-V8-2026-11-05.ts`.
- New source: `supabase/functions/bharatmail-inbound-webhook/index.ts` and `auto-metadata.mjs`.
- Repository regression: `bharatmail-dkim-test/tests/auto-inbound-metadata.test.mjs` (9 new scenarios; 63/63 total branch checks).
- **No MX, DNS, Resend domain claim, existing routing SQL, user-access RLS, Android APK, or physical file storage change.**

## Cross-account and deletion verification (live TEST database, 5 Nov)

- Verified existing metadata snapshot: exactly one user-owned snapshot, one metadata item.
- Non-owner `authenticated` role with test JWT subject sees **0 rows**; owner JWT subject sees **1 row**; `anon` SELECT is denied.
- Foreign key `bharatmail_received_snapshots_parent_owner_fk`: composite `(external_message_id,owner_user_id)` referencing inbox `(id,recipient_user_id)`, with `ON DELETE CASCADE`.
- **Transaction-only synthetic deletion test**: create an isolated fictional email and snapshot, delete only the fictional parent, confirm synthetic snapshot count **0** and pre-existing real snapshot count **1**, then **ROLLBACK**. No real email or saved snapshot was deleted.
- External client cross-account penetration test still requires separate authenticated test identities before production approval.

## Reliability limitations

Automatic capture is **best-effort, at receipt time**, not a guaranteed queue with retries. A provider outage, timing issue, incomplete metadata, DB failure or timeout can cause a missed automatic snapshot; the existing owner-triggered `Save attachment metadata securely (TEST)` button remains a fallback. Existing historic emails are **not silently backfilled**. An automatic v9 capture with a newly received attachment is not yet confirmed until the next controlled real inbound attachment test and independent DB read-only count.

Metadata remains linked to the owner via RLS and is retained until the parent email is deleted, subject to separately governed database backups. **No file bytes are scanned; no malware, sender identity, organization, employee, bank, authority, or payment is verified.**

## Production HOLD

Do not enable production release or a “Safe file”/“Verified Sender” badge. Need webhook retry/observability, security review, cross-account physical-client tests, data-retention governance, independent malware scanning, Resend support domain-claim resolution, SPF, and Android approvals.
