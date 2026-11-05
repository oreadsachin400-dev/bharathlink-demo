# BharatMail TEST — Durable attachment metadata snapshot v1
Date: 5 November 2026

## Scope & evidence
- User-confirmed Android Chrome real email attachment metadata lookup: Resend returned **one** metadata record on 5 November 2026, 16:15 IST.
- Previous `bharatmail_external_attachments` table requires `storage_path NOT NULL` and is for actual stored attachments. **Do not fabricate paths, change that table or download files.**
- New `public.bharatmail_received_attachment_snapshots` stores **at most one complete metadata-only snapshot per owned inbound external message**.
- This phase is **user-triggered via a separate TEST button**, not automatic persistence on every inbound email. Automatic webhook-side ingestion and backfill of older messages remain future work.

## Database
- One row per email: `external_message_id` primary key, `owner_user_id`, `items` JSONB, generated count, provenance `resend_receiving_attachments_api`, `captured_at`.
- Composite foreign key `(external_message_id, owner_user_id)` ensures recipient binding to existing message; `ON DELETE CASCADE` deletes the snapshot when the email is deleted.
- Owner-scoped RLS SELECT requires authenticated `auth.uid()` and a matching inbound parent row. `anon` has **no SELECT**; `authenticated` has SELECT only, **no INSERT/UPDATE/DELETE**; `service_role` writes via the server only.
- At most 20 nonempty items with a total serialized size no more than 32 KiB; metadata-only sanitized objects `{filename,content_type,size_bytes}`. No Resend attachment ID, download URL, storage path, file bytes, body or sender address is persisted.
- Immutable first snapshot: `on_conflict=external_message_id` with `resolution=ignore-duplicates`; existing rows are not overwritten by a later request. A verified owner-only database readback is required before the server labels the response `saved_snapshot`.
- **Retention:** durable until the parent email is deleted, not a claim of indefinite storage after account deletion. Backups, privacy deletion policy and any future time-based purge must be designed separately.

## Isolated Edge backend
- `bharatmail-attachment-snapshot-test` with `verify_jwt=true` is a new endpoint; does not replace existing `bharatmail-attachment-metadata-test` read-only endpoint, email routing, or Resend webhook.
- Re-checks user JWT via Supabase Auth; validates one received email through the user's own JWT and recipient RLS; checks saved snapshot with user JWT RLS **before** calling the provider.
- On cache miss, server fetches Resend **attachment list metadata only** with server-owned key. It never reads or returns download URLs or file bytes.
- If provider metadata is absent, partial, truncated, invalid, or write/readback fails, no saved claim is issued: `persistence: not_saved` / clear error. No fake "safe" verdict.
- Supports legacy `SUPABASE_SERVICE_ROLE_KEY` and new hosted `SUPABASE_SECRET_KEYS.default` server-only (never used by static website or returned in responses). <https://supabase.com/docs/guides/functions/secrets>.
- Repeated owner requests use the saved snapshot even if the provider later drops old attachments.

## Security tests
- `bharatmail-dkim-test/tests/received-attachment-snapshot.test.mjs`: owner vs stranger, JWT, cached retry, no duplicate insert, provider failure, partial lists, no secret URL leakage, storage failure, UI acknowledgment.
- Prior tests for inbound metadata, synthetic attachment metadata, ICICI/Reliance lookalikes and privacy redaction remain in CI.
- No external HTTP in unit tests; outbound provider and database calls are mocked.

## Not proved / remaining gates
- **No live database snapshot has been created until the user taps the new TEST button on a valid inbound message and receives `METADATA SNAPSHOT SAVED`.** No local test can substitute for an actual authorized phone test.
- No real file bytes scanned; filename/MIME/size are untrusted metadata. Sender, organization, bank authority and payment beneficiaries stay NOT VERIFIED.
- Existing Resend domain-claim support reply, trusted SPF, durable auto-ingest, native Android APK, security review and production rollout remain pending. **No DNS or MX modifications.**
