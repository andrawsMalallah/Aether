# Aether

An SSO identity provider built with Laravel 13. This foundation includes a placeholder welcome page and quality tooling; authentication and OAuth are subsequent roadmap steps.

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

Review `.env.example` before creating `.env`. The template uses `aether.test`, the `aether` MySQL database, database sessions and queues, UTC, and local Mailpit on port 1025. Create the local database and generate the application key only after approving local configuration. Point Herd at this directory as `aether.test`; serve its `public` directory.

Once local setup is complete, open `http://aether.test` to check the welcome page. `npm run dev` starts the asset development server; `npm run build` produces assets for deployment.

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
