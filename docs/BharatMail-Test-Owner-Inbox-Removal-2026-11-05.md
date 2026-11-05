# BharatMail TEST — Owner-confirmed Received Inbox Removal

Date: 5 November 2026. Scope: TEST only; no actual user email deleted during build or verification.

## What this feature does
- Adds **Remove this received TEST email and saved metadata** button for each received item in the TEST inbox.
- Requires two explicit user interactions: confirmation dialog and typing exactly `REMOVE`.
- Uses the existing signed-in user's Supabase JWT with a PostgREST `DELETE`, restricted to that message's UUID and `direction=inbound`.
- Requires `Prefer: return=representation`; treats the operation as confirmed only if exactly one deleted row with the requested UUID is returned. Checks that the owner-visible attachment metadata snapshot is absent before updating the UI. If network or readback fails, shows **Removal NOT CONFIRMED** and asks to refresh.
- SQL enables only `authenticated DELETE` on `public.bharatmail_external_messages` with `USING(recipient_user_id=(select auth.uid()) AND direction='inbound')`.
- Anonymous users cannot delete, unrelated signed-in users cannot delete another owner's received row, and outgoing rows are protected. No direct client DELETE permission is granted on attachment metadata.
- Existing composite FK on `bharatmail_received_attachment_snapshots` cascades when the parent message is removed. Existing incoming event routing, signature checking and v9 webhook are untouched.

## Guard against orphaned private file bytes
- A private-schema trigger `bharatmail_private.prevent_inbox_delete_with_stored_files` prevents deletion whenever the message has rows in `bharatmail_external_attachments`.
- This deliberately fails closed until a separate verified Storage-object cleanup flow exists; deleting DB metadata must not leave previously stored file objects orphaned.
- Guard function lives outside exposed `public`, with the schema and function revoked from ordinary roles; it only checks linked DB rows and never accesses file contents.

## Deletion does NOT mean full erasure
This action removes a received **TEST inbox row** and its attached metadata snapshot, provided no stored-file references block the request. It does NOT erase:
- The original sender's Gmail copy, the Resend provider's retained data, or other recipients' copies.
- The signed `bharatmail_inbound_events` event/payload (which can still include full message content), external backups, logs and replicas.
- Downloaded files, storage objects or device data; actual stored-file references cause the operation to be blocked until cleanup is implemented.

No statement of GDPR/legal complete erasure or regulatory-compliant retention is made. Provider deletion/retention controls need an independent design and audit.

## Verification
- Real data before and after rollback-only tests: **10 received emails, 2 metadata snapshots, 0 stored attachment rows**. No original user data modified by tests.
- Database grants: `anon DELETE=false`, `authenticated DELETE=true`, metadata snapshot `authenticated DELETE=false`.
- Transaction-only synthetic inbound message + snapshot: unrelated user's JWT affected **zero rows**; correct owner removed exactly one synthetic row; snapshot cascade confirmed; rollback restored baseline.
- Transaction-only synthetic outgoing message: own authenticated identity DELETE affected **zero rows**.
- Transaction-only synthetic inbox + stored-file reference: even correct owner was blocked by the private guard, preserving both DB rows; rollback removed all synthetic artifacts.
- GitHub CI validates CSP hash, explicit confirmation sequence, signed-in JWT, strict UUID and exact returned row, metadata readback, and no misleading original-provider erasure claims.

## Next gates
- Real physical phone interaction for safe CANCEL path and explicit owner-approved removal of a deliberately created test email (not an existing personal message).
- Fully audited provider-side delete and Storage byte lifecycle with privacy retention policy and backups.
- Independent third-party security review; sender identity, file malware, and production Android launch remain HOLD.

Relevant source:
`supabase/sql/bharatmail_owner_received_inbox_delete_v1.sql`
`supabase/sql/bharatmail_received_delete_stored_file_guard_v1.sql`
`bharatmail-dkim-test/index.html`
`bharatmail-dkim-test/tests/owner-delete.test.mjs`.
