# Aether

An SSO identity provider built with Laravel 13. The account core includes registration, Fortify login/logout, email verification, password reset, profile photos, password changes, and verified email changes. OAuth and two-factor authentication are subsequent roadmap phases.

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

## Quality commands

- `composer test`: Pest feature and unit tests.
- `composer lint` / `composer format`: check or apply Pint formatting.
- `composer analyse`: Larastan, minimum level 6.
- `composer check`: formatting check, static analysis, and tests.

## GitHub Actions

`.github/workflows/ci.yml` runs quality, tests, and assets jobs on pushes and pull requests. It is also manually runnable. Each job must pass.

After the workflow has been pushed and run, enable a GitHub branch ruleset for `main`: require pull requests, require status checks (`quality`, `tests`, `assets`), and require branches to be up to date. CI is not enforced by branch protection until the repository owner enables these settings. Local commits and pushes are not blocked by GitHub checks.

## Project guidance

Read `AGENTS.md` and `guide/MEMORY.md` at session start. The roadmap and architecture, security, testing, hosting, and design references live in `guide/`.
