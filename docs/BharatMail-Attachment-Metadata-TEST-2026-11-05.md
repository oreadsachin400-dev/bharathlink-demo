# BharatMail TEST v7 — Attachment metadata-only cautions

Reviewed 5 November 2026. Scope: synthetic local tests and read-only **owner-scoped** attachment metadata, not attachments themselves.

## Database evidence (read-only audit)

- The live TEST Supabase project `fsdusofbpwdrdvgexxyw` already has `public.bharatmail_external_attachments` with `external_message_id`, `direction`, `filename`, `content_type`, `size_bytes`, and owner fields.
- Existing `bharatmail_external_attachments_read_own` SELECT RLS: `owner_user_id = auth.uid()`. RLS on both attachments and messages is enabled. No RLS policy/DDL changed.
- 5 November 2026 aggregate SQL returned **0 external attachment records**. Real-inbox attachment warning behavior is **not yet confirmed on a physical phone with a stored attachment**. It must not be marked as live malware detection.

## Actual TEST inbox action

Only after the signed-in owner taps **Inspect attachment metadata (no download)** for an inbound email:

1. Query a single matching *inbound* `bharatmail_external_messages` row through existing Bearer JWT + recipient RLS; match the selected message ID and sender.
2. Query `bharatmail_external_attachments` using the same JWT + attachment owner RLS, same `external_message_id` and inbound direction, select exactly: `external_message_id,direction,filename,content_type,size_bytes`. Max **21** returned to detect exceeding the 20-entry local scan limit.
3. Reject a mismatched parent ID, direction, malformed response or unauthenticated session. Call only `attachment-metadata.js`, a pure local module.
4. Display bounded, generic warning explanations **without printing filenames, file paths, provider keys, file IDs or direct URLs**. Zero stored records are presented as **no attachment metadata stored**, not proof that original email lacked attachments.

It does not request `storage_path`, `provider_attachment_id`, cryptographic keys, raw MIME, attachment bytes, signed download URLs, or a virus scanning service. No new client-origin outbound endpoint is added.

## Bounded warning heuristics

- Executable/launchable/script extensions: `.exe`, `.scr`, `.js`, `.vbs`, `.bat`, `.cmd`, `.ps1`, `.jar`, `.msi`, `.lnk`, `.iso`, etc.
- Double-extension camouflage such as `invoice.pdf.exe`.
- Macro or active content `.docm`, `.xlsm`, `.pptm`, `.html`, `.svg`.
- Untrusted filename/MIME disagreement for selected known document/image types. MIME values and filenames are sender- or provider-supplied metadata, **not file-signature proof**.
- Filename Unicode bidi/zero-width control, NFKC normalization change, trailing dot/space.
- Greater than 25 MiB conservative caution (not a hard product size limit).
- Unknown/absent metadata, malformed fields, unclassified extensions, more than 20 metadata rows → incomplete warning or unknown coverage.

All results are **metadata_only**, `fileBytesInspected=false`, `malwareScanned=false`, `isAttachmentSafe=false`, `isMalwareProven=false`, and sender/organization identity NOT VERIFIED. Nothing in this phase calls an attachment safe or malignant.

## Synthetic demo / test evidence

- `bharatmail-dkim-test/attachment-demo.html`: 6 fictional metadata examples, with no file upload, access or login. CSP SHA-256 allowlist and SRI pin on same-origin local module.
- `bharatmail-dkim-test/tests/attachment-metadata.test.mjs`: adversarial extension, Unicode, MIME, size, empty/incomplete and owner-authorization UI checks.
- Existing `content-caution.test.mjs`: must remain passing, and both suites run in GitHub Actions. Existing email, DKIM/DMARC, company reference demo, redacted reporting and user-confirmed browser PASS results are preserved.

## Non-goals / open blockers

Actual file malware inspection requires a dedicated, authorized, isolated safe scanning service with size/format controls, sandboxing, decompression-bomb limits, antivirus signatures, privacy and retention policies, and independent review. No automatic download/opening of received attachments. SPF evidence, independently verified bank/person identity, Resend support reply, Play Protect decision, Android APK and production release remain pending/HOLD. No DNS, Resend, Supabase schema, attachment Storage, or Android signing changes.
