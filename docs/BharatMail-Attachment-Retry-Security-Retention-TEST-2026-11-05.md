# BharatMail TEST — Automatic Attachment Metadata Retry, Privacy & Retention v1
Date: 5 November 2026. Project: \`fsdusofbpwdrdvgexxyw\` (TEST only).
No changes to Resend MX/DNS/domain claim, mail routing SQL, signed inbound webhook v9, user-facing inbox, Android APK or production.

## Previously verified
- Signed Resend inbound webhook v9 (post-routing, best effort) successfully saved one real attachment metadata snapshot automatically at 18:04 IST on 5 November 2026.
- Metadata-only \`bharatmail_received_attachment_snapshots\` already had owner-only SELECT RLS, composite FK to received email, one immutable snapshot per email, and ON DELETE CASCADE.
- Failure modes were not reliably re-attempted: an API outage or transient timeout could leave a routed email without metadata forever.

## New recovery design — no changes to the signed webhook
1. A separate five-minute Postgres cron job (\`blmail-attachment-retry-v1\`) runs as \`postgres\`. It **only** considers received email rows created **after the retry migration's activated_at timestamp**, and only if they lack an attachment metadata snapshot. No historic backfill.
2. The enqueue step stores only the server-side provider email UUID, a coarse retry status, attempt count and timestamps in \`bharatmail_attachment_retry_jobs\`. The public-schema table has RLS **enabled with no user policies**, and all access is revoked from \`public\`, \`anon\` and \`authenticated\`. This is intentional deny-all to clients.
3. A 32-byte random HMAC secret is generated **inside PostgreSQL** and encrypted in Supabase Vault. Cron signs a per-invocation timestamp plus random UUID nonce with HMAC-SHA256. Only the timestamp, nonce and signature—not the secret—are sent via \`pg_net\` HTTPS to the isolated Edge worker. Signature is checked server-side by a locked-down \`SECURITY DEFINER\` function callable only with the service-role key. The timestamp is limited to ±120 seconds, and each nonce can be used exactly once (unique database entry). Signature reuse is rejected. No credential is hardcoded in GitHub or cron command.
4. The worker \`bharatmail-attachment-retry-test\` runs with Edge gateway \`verify_jwt=false\` **because it performs independent Vault-backed HMAC authentication before any queue claim**. It fetches its own service role and Resend keys from server environment, never user input. It claims at most three due rows atomically with \`FOR UPDATE SKIP LOCKED\` and a 90-second lease. The worker does not accept provider UUIDs, URLs, recipients or attachment bytes in request bodies.
5. For each claimed job it reuses the audited \`captureInboundAttachmentSnapshot\` helper that validates actual routed parent rows and reads the Resend **attachment LIST metadata only**. No attachment download URLs are followed and no file bytes are inspected. Snapshots remain immutable, owner-bound and must read back successfully before a saved result.
6. The finalizer marks \`saved\` only on confirmed metadata persistence, \`empty\` only when provider returned no metadata, and otherwise retries after bounded exponential backoff. Failed RPC finalization leaves the lease for a safe re-claim. No success label is invented.
7. At most **5 attempts** over **48 hours**; no infinite polling. Jobs expire to \`dead\` after the retry window. Concurrency is bounded by the worker and database leases. A provider-reported empty list **does not prove** the original email contained no attachment. New sent messages or unrelated files are never processed.

## Retention policy
| Artifact | Retention |
| --- | --- |
| Real received attachment metadata snapshot | **Until its parent received email is deleted by an authorized workflow**, by existing ON DELETE CASCADE; user-facing delete flow must be independently implemented and tested |
| Pending/retry job | At most 48 hours / 5 attempts; then terminal |
| Terminal job status (no message body or filename) | 7 days after completion, then cron cleanup |
| HMAC replay nonce (UUID only) | 1 day, then cleanup |
| Resend metadata and any original attachment bytes | NOT downloaded or retained by this worker |
| Backups/replicas/provider-side retention | Not controlled by this feature; separate privacy governance required |

Deleting an email is not falsely simulated as an end-user feature: only a rollback-only synthetic database cascade test and owner access tests are currently verified. It would be incorrect to assert that users already have an independently tested self-service metadata deletion action.

## Evidence
- New SQL: \`supabase/sql/bharatmail_attachment_retry_queue_v1.sql\`, \`bharatmail_attachment_retry_scheduler_v1.sql\`, \`bharatmail_attachment_retry_cron_v1.sql\`.
- New Edge: \`supabase/functions/bharatmail-attachment-retry-test/index.ts\`, \`retry-worker.mjs\`, and unchanged reusable \`auto-metadata.mjs\`.
- Tests: \`bharatmail-dkim-test/tests/retry-security-retention.test.mjs\`, plus all earlier BharatMail tests; mock external calls, validate authorization first, no file access, rate bounds, retry finalizer failures, retention.
- Live verification: a Vault HMAC signature was accepted, identical nonce replay rejected; a signed \`pg_net\` invocation returned HTTP 200 and processed zero jobs when no newly eligible mail existed. A rollback-only synthetic pending job transitioned to \`retry\` with positive backoff and released lease; rollback left no synthetic rows.
- Supabase security advisor warns for new retry tables with RLS and no policies. **Intentional** because authenticated and anonymous roles have no table privileges and all user policies are withheld. Service-role-only privileged RPC functions explicitly revoke \`PUBLIC\`, \`anon\` and \`authenticated\` execute.
- Existing calling and messaging cron jobs remain active/unchanged.

## Open gates
- A real provider outage then recovery, with a NEW post-activation received attachment, has not been deliberately induced on a physical phone. Do not claim perfect retry reliability or guaranteed delivery.
- A real second authenticated user cross-account penetration test remains pending; database-level RLS negative control for existing snapshots passed.
- External independent security assessment, audit log retention/PII review, true self-service deletion controls, Resend domain-claim support, trusted SPF, legal/role/beneficiary verification, malware scanning and Android production release remain HOLD.
- No sender, bank/organization, payment or attachment is certified safe by metadata.
