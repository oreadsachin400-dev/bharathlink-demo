# BharathLink Mail — Real DKIM Cryptographic Verification (STAGED, NOT DEPLOYED)

4 November 2026. Branch: `bharathlink-mail-dkim-cryptographic-offline-ci`.

## Verified result

- [GitHub DKIM CI #41821891666](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41821891666): **13/13 DKIM tests PASS**.
- `mail-verifier/verify-original-dkim.mjs` calls maintained `mailauth@8.0.0`'s real `dkimVerify` in strict mode with RSA minimum 2048 bits and SHA-1 disallowed.
- Tests generate an ephemeral RSA-2048 private/public key in memory, DKIM-sign a synthetic MIME email, and verify the signature against an injected synthetic DNS TXT key. Tampered bodies, wrong DNS keys, forged `Authentication-Results`, invalid or ambiguous From addresses, wrong sender, different signing domain, oversized MIME and DNS failures never produce an aligned PASS.
- Additional negative tests reject DKIM signatures using `l=` partial-body coverage and keys marked `t=y` testing-only. No authority badge or payment approval is granted.
- Real DKIM verification checks the **original MIME bytes**, exactly one valid signed From address, the signed `d=` domain matching the expected sender domain, and rejects body-length-limited DKIM signatures. This is stricter than relaxed organizational-domain alignment.
- An independent DNS resolver must be injected; the module never chooses a default public DNS source implicitly. Its actual trustworthiness and production key-record custody remain separate external gates.

## Combined regression

- [GitHub Actions run #41822446724](https://github.com/oreadsachin400-dev/bharathlink-demo/actions/runs/41822446724): **2/2 jobs SUCCESS; 13/13 DKIM cryptographic tests plus 142/142 existing Mail Trust and earlier security tests = 155/155 PASS** (zero failures or skips).
- No APK, staging deployment, new DB migration, real-email fetch, or production issuer activation.

## What DKIM PASS means

It proves that the **holder of the DKIM domain's published private key** signed certain message headers and body portions, assuming a trustworthy DNS TXT answer and correct verifier implementation. It **does not prove** the human identity, job/authority, banking legitimacy, payment beneficiary, a safe link, or that an urgent request is genuine.

SPF is `not_checked` because Resend has not supplied a verified connecting SMTP IP and envelope MAIL FROM for the audited existing TEST flow. DMARC is `not_checked` because a complete policy/alignment assessment is not yet integrated. None of these fields is promoted to a `Verified Person` badge. The existing BharathLink Mail web UI remains unmodified and its sender authentication remains `not checked`.

## Release HOLD

No live Supabase, Resend, Netlify, DNS/MX, SMTP or Android APK is modified. No real customer message was retrieved by these tests. This is **offline implementation** and should not be deployed until a controlled receiving-verifier service, trusted DNS resolution, independent signer keys, and policy/legal review are available.

Source library documentation: https://github.com/postalsys/mailauth (DKIM `dkimVerify`, `strict:true`, custom DNS resolver).