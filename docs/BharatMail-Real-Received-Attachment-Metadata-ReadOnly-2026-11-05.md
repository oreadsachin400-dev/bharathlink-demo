# BharatMail TEST — Real provider attachment metadata (owner-authenticated, on demand)

5 November 2026. **No inbound webhook, DNS, Resend domain-claim, MX, mailbox routing, or production APK modifications.**

## Live audit finding

- `public.bharatmail_inbound_events`: 15 rows; saved `payload.email.attachments` arrays have a total of **0** metadata items.
- `public.bharatmail_external_messages`: 7 inbound rows; `public.bharatmail_external_attachments`: **0** rows.
- Current signed `bharatmail-inbound-webhook` v8 stores only `filename` and `content_type` from provider's received email detail. It does not preserve `size` or attachment ID.
- Current `bharatmail_route_inbound_event(text)` inserts received email messages but does not write corresponding rows into `bharatmail_external_attachments`.
- That existing attachment table requires `storage_path NOT NULL`, meaning it is intended for actually stored files, **not an appropriate place for un-downloaded metadata-only rows**. Do not insert fake storage paths, relax the constraint blindly, or claim these rows are malware-scanned.

This audit cannot determine whether any of the existing real emails originally contained attachments; historical provider retention is not guaranteed.

## Safer zero-routing-change read path

A separate `bharatmail-attachment-metadata-test` Edge endpoint:

1. Accepts a user JWT and an **internal** received message UUID; never trusts a user-supplied provider ID.
2. Rechecks JWT via Supabase Auth `/auth/v1/user`, then SELECTs **exactly one** inbound `bharatmail_external_messages` row via the **same user's JWT and RLS**; verifies `recipient_user_id`, `direction` and IDs.
3. Reads the resulting internal `provider_email_id` only on the server; requests `GET https://api.resend.com/emails/receiving/{id}/attachments?limit=21` using the server-only `RESEND_INBOUND_API_KEY`. No original email body or attachment bytes are fetched.
4. Produces at most 20 sanitized `filename`, `content_type`, and `size_bytes` records. Rejects oversized/invalid replies, marks missing fields or pagination as partial, never follows/stores/returns `download_url` or provider attachment IDs.
5. The user-initiated TEST inbox button runs the existing pure local metadata caution engine and displays **metadata only / malware not scanned / file safety not established**.
6. An authenticated empty provider list means only **no metadata returned by provider now**; it is not proof no attachment existed historically.

Browser origin is restricted to the exact GitHub Pages site. Gateway uses POST only and has no write path. User/browser cannot supply an alternate URL, Resend ID, storage path or account token. Response and browser do not show secrets, emails, sender IDs or attachment download URLs.

## Verification

- Synthetic Node tests exercise owner validation, IDOR denial before provider fetch, untrusted input, failed provider requests, URL suppression, payload truncation, oversized JSON and incomplete metadata states.
- Existing content, domain-reference, redacted-report and 6 fictional attachment metadata tests must remain passing.
- Phone/browser test with an actual stored received attachment is **NOT complete** unless a controlled real attachment reply is first sent and the provider returns metadata. Do not mark end-to-end PASS just because the no-attachment path displays.

## Dependencies / blocks

- This endpoint is a live **read-only diagnostic**, not a durable ingestion pipeline. Persistent attachment records and actual file scanning need separately audited integration, retention and storage plans.
- All domain/DKIM/SPF/verified person, bank/role, payment authority and APK/production gates remain unchanged and HOLD.
- Resend support's domain-claim response remains pending; do not click Start over or replace DNS.
