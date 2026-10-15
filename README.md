# Aether

An SSO identity provider built with Laravel 13, Fortify account authentication and confirmed two-factor authentication, and Passport OAuth2 with an OpenID Connect identity layer. Discovery, JWKS, scope-filtered userinfo, and standard signed ID tokens support basic "Sign in with Aether" integration. The developer portal, administrative client lifecycle and audit viewer are implemented; production hardening remains ongoing.

## Requirements

- PHP 8.3+ and Composer 2 (Windows: Laravel Herd).
- Node 24 LTS recommended; Node 22.12+ is also supported.
- MySQL/MariaDB for the application; Mailpit for local email.

## Install and check

```powershell
composer install
npm ci
composer check
composer audit
npm audit
npm run build
```

`composer install` discovers packages but does not create `.env`, generate keys, or run migrations. Tests use an isolated in-memory SQLite database locally. CI overrides the connection to use its own disposable MySQL database. No production database is needed for checks.

## Local application setup

Review `.env.example` before creating `.env`. The template uses `aether.test`, the `aether` MySQL database, database sessions and queues, UTC, Argon2id, and local Mailpit on port 1025. Configure database credentials privately in `.env`; never paste them into chat or commit them. Create the local database and generate the application key only after approving local configuration. Point Herd at this directory as `aether.test`; serve its `public` directory.

Once local setup is complete, open `http://aether.test` to check the welcome page. `npm run dev` starts the asset development server; `npm run build` produces assets for deployment.

After confirming the database is a local development database, run normal `php artisan migrate`. Do not use `migrate:fresh` or `db:wipe`. Start Mailpit, then run `php artisan queue:work` so verification and reset emails are delivered. Queue workers must be restarted after application code or configuration changes.

## Account behavior

- Registration keeps the browser signed out and returns the same message for new and existing addresses. New accounts receive a queued verification email; sign in with the newly chosen password to continue.
- Accounts must verify their email before accessing `/account/profile`.
- Forgot-password responses are identical for known and unknown addresses. Reset tokens are managed by Laravel's password broker and cannot be reused.
- Profile photos are validated, stored under generated names on the private local disk, and served only to their owner.
- Password changes require the current password, revoke other database sessions and remember-me credentials, and cancel pending email changes. Password resets revoke all database sessions.
- Email changes require the current password. The original address remains active until the new address is confirmed using a signed, expiring link while signed in as the account owner. Both addresses receive queued notifications.
- Auth pages load fonts and other assets from this application. Password validation contacts Have I Been Pwned using Laravel's k-anonymity verifier; tests fake those responses and block unexpected HTTP calls.
- Terms and privacy pages are clearly marked draft placeholders and need real text before launch.

## Manual verification

On desktop and a 320px-wide mobile viewport:

1. Open `/register`, create an account, and inspect the verification mail in Mailpit. Sign in, open the link, and confirm access to `/account/profile`.
2. Sign out, then test `/login` with an incorrect password and with remember-me enabled.
3. Use `/forgot-password`, open the mail link, reset the password, and confirm that the same link cannot reset it again.
4. On `/account/profile`, update the name, upload a JPEG/PNG/WebP photo, and check rejection of oversized images or SVG files.
5. Change the password using the current password; confirm another browser session is signed out.
6. Request an email change. Confirm the old address remains active before confirmation, then follow the new address's link while signed in. Confirm the old address receives a notice.
7. Use keyboard navigation to check labels and focus rings; confirm all forms fit the mobile viewport.

Automated checks are isolated. Live MySQL, Mailpit, and GitHub Actions verification must also pass before marking Phase 1 complete.

## Two-factor authentication

Open `/account/security` after verifying your email. Confirm your password (valid for five minutes), start setup, scan the QR code or enter the manual setup key in your authenticator app, and confirm a six-digit code. Setup is inactive until confirmation. Save the recovery codes shown after confirmation; they are not shown on subsequent visits. Generating replacements invalidates all previous codes.

On desktop and a 320px mobile viewport, verify setup and cancellation, sign-out/sign-in with TOTP, sign-in with a recovery code followed by rejection of its reuse, recovery-code regeneration, and disabling 2FA. Check that an incorrect code leaves you signed out, the sixth challenge attempt within a minute is blocked, and settings require password confirmation again after five minutes. Verify keyboard focus and that the QR code, setup key, and recovery codes fit the screen. A code just used to confirm setup cannot immediately be reused for login; wait for the next authenticator code.

Fortify encrypts the secret and recovery codes with `APP_KEY`. Do not rotate that key without a planned re-encryption process. The security page sends `Cache-Control: no-store` and one-time credentials are excluded from flashed form input.

The application's Fortify provider adapter records the actual accepted TOTP time step using an atomic cache claim, preserving clock tolerance while preventing reuse. Replay protection requires a shared persistent cache (the local default is database); clearing or evicting live claims removes that protection until those codes expire.

## OAuth2

Passport 13.9 uses UUID clients, polymorphic owners, `redirect_uris`, and `grant_types`. Aether extends its client model with explicit trust, lifecycle, app type, and allowed scopes. Secret hashing is built into Passport; `plainSecret` is available only on the instance that created/regenerated it and is never stored as plaintext. No HTTP client-management or personal-access-token endpoints are exposed.

After confirming the configured database is local, run normal `php artisan migrate`, then `php artisan passport:keys` once. The default is 4096-bit RSA; never force-overwrite an existing pair. Keys are ignored under `storage/`. Production uses `PASSPORT_PRIVATE_KEY` / `PASSPORT_PUBLIC_KEY` from its secret store; no `.env` change is needed for the local file-based defaults.

`php artisan db:seed --class=OAuthTestClientSeeder` creates one public local walkthrough client with exactly `http://localhost:8765/callback`. It is local-only, idempotent, live, and third-party (consent required). It creates no user and prints no secret. Do not run the fixture seeder in production.

Interactive clients require authorization code + PKCE S256, including confidential web clients. Redirects match registered strings exactly, including loopback ports. SPA/mobile clients are public; web/M2M clients are confidential. Only live confidential M2M clients can use client credentials. Testing clients allow only their verified owner; suspended/revoked clients cannot authorize, exchange, refresh, or use existing access tokens.

Authorization codes last one minute; access tokens last one hour; refresh tokens last 30 days and rotate. Database transactions and row locks serialize code/refresh consumption. Code replay revokes all access/refresh tokens in its lineage, including refreshed tokens. Minimal database audit records (`code.replayed`, `refresh.replayed`, `consent.granted`, `token.revoked`) contain event/client/user IDs, never raw credentials. The wider audit catalog is a later phase.

Consent persists independently of token expiry, unions approved scopes, and re-prompts for expansion or revoked grants. The explicit `first_party` flag skips consent; ownerless clients do not automatically become trusted. `prompt=consent` forces a prompt. Consent submissions bind to the signed-in user and recheck current restrictions.

`POST /oauth/token`, `/oauth/revoke`, and `/oauth/introspect` are stateless back-channel protocol routes. Browser consent remains protected by web session/CSRF middleware. Confidential clients authenticate with Basic **or** body credentials, never both. Revocation accepts either token type, checks client ownership, revokes the associated access/refresh pair, and returns an empty 200 for unknown tokens. Introspection is restricted to explicitly permitted resource clients and supported machine access tokens.

See [scripts/oauth-walkthrough.md](scripts/oauth-walkthrough.md) for the complete manual flow. Check consent, Allow/Deny, return visits, expanded scopes, and keyboard focus on desktop and a 320px mobile viewport. OAuth tests generate ephemeral signing keys and never use local provider keys. Run `composer check`, `composer audit`, and `npm run build`; hosted CI remains a separate publication gate.

## OpenID Connect

Discovery is at `/.well-known/openid-configuration`; public signing keys are at `/.well-known/jwks.json`. The issuer comes from `config/oidc.php` (canonical `APP_URL`), never the request Host header. HTTP is allowed only in local/testing; production requires HTTPS. ID tokens use standard RS256 through the existing JWT library and Passport's RSA keys, with a stable public-key thumbprint as `kid`.

User grants requesting `openid` receive a one-hour ID token. `sub`, issuer/audience/timestamps, and original login `auth_time` are included. The authorization request's optional `nonce` is bound to the stored code and cannot be replaced at consent or exchange. Refresh keeps the original authentication time and nonce; reduced scopes reduce identity claims. Context is copied onto access-token records so expired-code cleanup does not break refresh. Machine grants and grants without `openid` do not receive identity tokens.

`GET` and `POST /oauth/userinfo` accept an Authorization Bearer header, not browser login cookies. They require a valid user access token with `openid`, enforce current client/account restrictions, and return only scope-granted claims: `name` for `profile`, `email`/`email_verified` for `email`. Private avatars do not currently have a client-readable URL, so the optional `picture` claim is omitted. Invalid/expired/revoked credentials return 401; a valid credential without the required identity scope returns 403. Identity responses are not cacheable.

Existing sessions without recorded login time must sign in again for OIDC. Pre-upgrade codes/refresh credentials with `openid` but no authentication context are rejected safely; clients must restart sign-in. The OIDC migration adds nullable context fields to authorization codes and access tokens. Apply it with normal `php artisan migrate` against a confirmed local database before testing.

Discovery advertises only authorization-code responses, query response mode, S256, RS256, public subjects, and supported claims. Request objects, request URIs, the claims parameter, `max_age`, `id_token_hint`, and `acr_values` are explicitly unsupported and rejected. Full conformance certification, multiple simultaneous public keys/key rotation, and logout protocols remain later work. `config/cors.php` starts with no allowed origins; opt in to exact approved browser-client origins in Phase 5. It covers only protocol/data endpoints and never permits credentialed browser cookies.

See [scripts/oidc-walkthrough.md](scripts/oidc-walkthrough.md) for manual checks. Phase 4 interoperability was exercised with an isolated `openid-client` 6.8.8 relying party using discovery only; that temporary tool is not an Aether dependency.

## Machine access and restricted introspection

Confidential machine clients use `client_credentials` with explicitly allowed scopes such as `stats:read`. Machine tokens have no human account, refresh token or ID token. The OAuth library uses the client identifier as the machine token subject; do not treat it as a user ID.

`POST /oauth/introspect` authenticates confidential resource clients and requires a privileged `introspection_client_ids` allowlist, which is outside developer self-service input and mass assignment. Only permitted live machine access tokens return metadata. Unsupported, expired, revoked or unauthorized tokens return `active:false`; invalid callers receive a safe authentication/authorization error. Header/form credentials and token input must never appear in logs or screenshots. This endpoint is not general user-token or refresh-token introspection.

The separate Waraq/Pocket resource apps and Pulse console client demonstrate scoped aggregate access with per-request revocation checking. They are independent repositories and are not included in this project. Prism is a separate Vue browser profile app at http://localhost:5173, using a public client, S256 and in-memory tokens. Owner verified live sign-in, session refresh and local sign-out. Remaining live consent, reload, returning SSO and signed-in desktop/320px/keyboard checks passed; the SPA validation requirement is verified.

## Quality commands

- `composer test`: Pest feature and unit tests.
- `composer lint` / `composer format`: check or apply Pint formatting.
- `composer analyse`: Larastan, minimum level 6.
- `composer check`: formatting check, static analysis, and tests.

## GitHub Actions

`.github/workflows/ci.yml` runs quality, tests, and assets jobs on pushes and pull requests. It is also manually runnable. Each job must pass.

After the workflow has been pushed and run, enable a GitHub branch ruleset for `main`: require pull requests, require status checks (`quality`, `tests`, `assets`), and require branches to be up to date. CI is not enforced by branch protection until the repository owner enables these settings. Local commits and pushes are not blocked by GitHub checks.

## Project guidance

Local AI instructions and planning/session notes are maintained separately from published application source.

## Developer portal

Verified users can activate developer access from their account and manage owned applications at `/developer/apps`. Lists are paginated and ownership checks include both owner type and ID. Self-service registration supports confidential Web and public Browser (SPA)/Mobile apps, using authorization code plus refresh grants, S256 PKCE, exact callbacks and identity scopes (`openid`, `profile`, `email`). New interactive apps start in Testing, where only their owner may sign in. Machine apps register through the Machine link on the registration page, with client credentials only, no callbacks and no initial permissions. Testing blocks Machine token issuance. Provider-wide trust and introspection permissions are never self-service inputs.

Web and Machine client secrets are hashed by Passport and shown once after registration or regeneration. Browser clients have no secret, credential handoff or regeneration action; client ID plus mandatory S256 PKCE is used. Application type is fixed at registration and cannot be converted through settings. The encrypted, application-bound session handoff is consumed on the authorized detail read, serialized with session blocking and served private/no-store. Store the secret in the integrating app's server environment; never put it in browser storage, source control or logs.

Owners can edit settings and publish Testing Web, Browser or Mobile apps to Live. Confidential Web and Machine apps can regenerate secrets; owners cannot activate Machine apps or change their approved permissions. Sensitive actions require a password confirmed within 300 seconds and explicit confirmation. Regeneration atomically revokes the app's access/refresh tokens and pending authorization codes in bounded batches. Callback changes cancel pending codes; removed scopes affect current token checks. Exchanges share the client row lock with lifecycle changes. Consent and existing client-local sessions remain independent of credential revocation.

Web, Browser and Mobile detail pages include the client ID, saved callbacks/scopes, canonical issuer and protocol endpoints with type-specific PKCE/OIDC instructions. Browser instructions cover client authentication method none, per-attempt state/nonce/verifier, in-memory tokens, rotating refresh and secretless revocation. Exact-origin CORS approval is a separate operator step: registration or Go live does not allow browser API requests. CORS permits only the exact http://localhost:5173 Prism origin in APP_ENV=local, without cookies. Deployed environments remain closed by default. Machine registration, settings/logo updates, one-time credentials, rotation, deletion and integration instructions are supported. Machine permissions and activation are approved by administrators from an owned Testing Machine app detail page; owners cannot grant access or activate services. Mobile registration and a native-app guide support HTTPS app/universal links only; a real native client/device walkthrough and broader executable examples remain unfinished.

Owners can permanently delete their confidential Web/Machine or public Browser/Mobile apps in Testing, Live or Suspended state after a recent password confirmation and explicit checkbox. Deletion retains the client record with revoked=true and records client.deleted; it atomically revokes access/refresh tokens and pending codes under the issuance lock. Revoked apps disappear from the developer list and their old detail/settings/credential/publication links are forbidden. Administrators retain read-only records and audit references; restoration remains forbidden. Current-session one-time secret handoffs are cleared, and revoked-client policy blocks handoffs in other sessions. Client-local sessions may remain signed in.

## Administration

Run normal migrations against an approved database before using administration. `users.is_admin` is privileged and not mass assignable. Admin pages require a verified account and confirmed Fortify two-factor authentication. Newly bootstrapped admins must enable and confirm 2FA under Security before entering `/admin/apps`.

The explicit `php artisan db:seed --class=AdminSeeder` bootstrap reads `ADMIN_NAME`, `ADMIN_EMAIL` and `ADMIN_PASSWORD` through config. Supply credentials privately, never in command history or source control. Passwords require at least 12 characters with uppercase/lowercase letters, numbers and symbols. The seeder is not called by default seeding, refuses to promote existing ordinary accounts or create additional first admins, and never resets an existing admin's password. Remove transient bootstrap configuration when no longer needed and handle configuration caches securely.

Administrators can list all applications, search by part of a name or exact client ID, and combine status/type filters. Revoked is separate from Testing/Live/Suspended; selected filters persist across twelve-row pages. Invalid queries return field errors on a usable clean page. Application details never reveal or consume an owner's one-time secret handoff.

Suspension requires recent password and explicit confirmation, stops sign-in/token issuance and atomically revokes app access/refresh tokens and pending codes. Restoration applies only to non-revoked Suspended apps and returns them to Testing; old credentials remain invalid. Both operations recheck policy under the same client lock as issuance and record an audit event. Restoration does not assign ownership, change secrets or publish. Web owners separately choose Go live; ownerless clients cannot sign in in Testing. Other app types retain publication restrictions. Client-local sessions may remain signed in.

`/admin/audit` is read-only and displays already-recorded application/OAuth events. Filter by action, exact client ID, exact actor email or user ID, and inclusive UTC dates. Results use newest timestamp/ID order with twelve-row pagination. Names are current lookup values, not historical snapshots; missing records retain their IDs. Replay/token-revocation user references identify the credential owner, not necessarily the requester. No credentials or raw requests are exposed. This viewer does not add missing event tracking.

`/admin/users` provides a read-only, twelve-row user list with literal name/email search and combined role/email-verification filters. Administrator and Developer filters include accounts with both flags; User means neither flag. Details show public account metadata, confirmed 2FA status, UTC join time, paginated applications constrained by owner type and ID, and a link to existing user-referenced audit events. No account or role actions are exposed. Passwords, 2FA material, session credentials and client secrets are excluded from output.

Existing ID/status and audit user/client/time indexes support these lists. Type/revoked/event filters have no dedicated indexes and contains-name search scans; profile at scale before choosing additional indexes. User name/email contains searches scan; is_developer and email_verified_at have no dedicated indexes. Profile representative data before adding indexes for these low-cardinality filters.

## Validation and manual review

Run `composer check`, `composer validate --strict`, `composer audit`, `npm audit`, and `npm run build` before publication. The current local suite has 345 tests / 2,893 assertions. Feature suites generate ephemeral signing keys and do not depend on local provider keys. CI additionally runs the suite on disposable MySQL.

Review new pages at desktop and 320px widths using Tab, Space and Enter. Automated protocol/template checks do not establish native OS callback delivery or production readiness.

- **Users:** as a verified administrator with confirmed 2FA, open `/admin/users`, combine search/role/verification filters, inspect account details, owned-app pagination and audit links. These pages are read-only.
- **Web:** register a disposable app, save its secret privately, reload to confirm hidden display, edit callbacks/scopes/logo and review the integration guide. Verify confirmed secret rotation invalidates old credentials. Test owner-only Testing and explicit Go live.
- **Browser:** register a Browser application, verify no secret/regeneration action, edit callbacks/permissions and review the browser guide/origin notice. Verify S256 sign-in, rotating refresh, reload behavior and local logout against a separately approved exact origin. Registration/Go live never enables CORS automatically.
- **Mobile:** choose Mobile application (native), register exact HTTPS app/universal links and verify no secret or regeneration action. HTTP (including loopback), custom schemes, credentials, fragments and wildcards must fail validation, including during settings edits. Review the native guide and confirmed Go live/deletion flows. Native platform/domain association and real installed-device sign-in remain separate integration verification; Aether does not configure or verify that association.
- **Machine:** use the Machine registration link, verify Testing/no permissions and one-time credentials. Owners can edit name/homepage/logo, rotate credentials or delete; they cannot grant permissions or activate. Testing token requests must fail.
- **Machine approval:** as a verified admin with confirmed 2FA and recent password, open an owned Testing service under Administration → Applications → Approve Machine application. Explicitly select `stats:read`, the intended resource APIs and readiness, then approve. Verify Live status, token issuance, selected API access, rejection by unselected APIs and an actor/client `client.machine_approved` audit event. No scopes/resources are selected automatically. Reapproval replaces previous grants and invalidates old tokens; other machines remain unaffected. Only already-configured Live confidential Web resource APIs are selectable. No owner approval-request inbox or new resource-registration UI is included.
- **Logos:** upload/replace PNG/JPEG/WebP (up to 2 MB and 4096 pixels per side) in Edit settings. Check square previews, initials fallback and consent/developer/admin displays. Empty upload preserves the image; SVG/oversized uploads fail. Images remain private and policy-protected; replaced files are retained.
- **Deletion:** use only a disposable app. Confirm password/readiness and verify it disappears from developer pages, credentials fail, the retained admin record is Revoked and restoration is forbidden. Do not delete existing integrations for a test.
- **Administration:** review application search/filters and audit pagination. Suspend a disposable app and verify immediate credential rejection. Restoration returns Testing without reviving credentials; Machine clients require another admin approval before issuing tokens. Existing interactive owners may separately Go live.

The local suite and synthetic desktop/mobile keyboard previews cover the provider portal and protocol paths. A real native app/device walkthrough, broader executable integration examples, final Phase 6 acceptance and production hardening remain outstanding. Integrating projects are separate and are not published with this repository.
