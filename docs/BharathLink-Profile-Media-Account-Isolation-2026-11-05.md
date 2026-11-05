# BharathLink TEST — Home profile photo/account mismatch fix
5 November 2026

## Observed bug
Home displays a Supabase-synced display name but draws the avatar from `Store.state.profileMedia.photoData`, a device-local `localStorage` field. The legacy field had **no owner UID**. Previous account-isolation reset was conditional on an existing last-user marker; legacy installs with a missing marker could carry a stale picture across an authenticated profile switch.

The Supabase TEST `profile_media` table currently has **zero rows** and neither of the two reported test display-name profiles has a remote photo path. Thus the image visible on the screenshot was not sourced from an existing remote profile-media row. This does not independently identify the pictured individual or prove which session originally uploaded the local image.

## Implemented
- Add a profile-media `ownerScope` tag. Signed-in media is tagged `auth:<Supabase UUID>` and local-only demo media `local:<accountId>`.
- ProfileAvatar/Home and profile controls now render photo only if scope matches the currently active identity. Status and stories in that local slice also require a matching scope.
- Upon sign-in/session restoration, **legacy unowned or mismatched local photo/status data is cleared**, before old local media could be published to a new signed-in account.
- Remote photo/status import checks that the provider's storage path starts with the current signed-in owner's UUID and intended `profile/` or `status/` folder. After download, data is persisted only if the active owner scope still matches.
- No automatic deletion or write to Supabase cloud photo, profile data, chats, mail, payments, encryption or caller data. An ambiguous legacy local photo may need to be re-selected under the correct account, intentionally fail-closed for privacy.

## Verification and limits
- Node privacy suite includes dynamic testing for ownerless photos, account switching, same-owner persistence, local-only account changes, scoped status, no-owner refusal, avatar rendering and backend-sync guard.
- Entire 800KB+ inline JavaScript bundle is parsed by Node VM as a syntax regression check.
- Existing BharatMail security suite remains in CI; no email or MX/Resend changes.
- **Real Android/browser confirmation remains pending:** reopen website after GitHub Pages deployment, allow refresh, verify the Nidhi TEST account shows initials or an explicitly uploaded Nidhi photo rather than a stale photo from another account.
- Owner binding **does not prove legal identity** or confirm a photo depicts the account holder. Profile verification, issuer and image provenance are separate features; never display a Verified Identity badge on image match alone.
