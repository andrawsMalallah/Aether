# Application image

The PHP platform uses the official PHP 8.3.35 Apache Trixie image pinned by digest. Build-time Debian version checks require Apache >=2.4.69-1~deb13u1, libssl3t64 >=3.5.7-1~deb13u3 and libexpat1 >=2.9.0-1~deb13u1. These minimums cover the reviewed security updates; they do not replace a fresh scan of the resulting image. Node's build-only stage and the isolated PostgreSQL fixture retain their independent Bookworm bases.

Build from the repository root using Docker Desktop's Linux engine:

```powershell
docker build --target runtime -t aether:packaging .
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/test-container.ps1 -SkipBuild
```

The test runner first exports BuildKit's actual context and checks that required sources are included while host assets, bootstrap caches, environment files and private paths are excluded. It creates uniquely named fixture resources and writes their inventory under ignored `storage/app/aether-container-*`. It generates throwaway credentials/signing keys, starts fresh PostgreSQL 18, Mailpit and Adobe S3Mock, and runs ordinary migrations only inside that fresh database. Dependency services have an internal network; web additionally has a bridge with an ephemeral port bound only to 127.0.0.1. It never mounts the real environment, keys or private storage. Resources and data remain for review; cleanup needs approval.

S3Mock's test-only filesystem overlay accepts its self-signed TLS certificate. The runtime image keeps the existing HTTPS/private-storage checks. Mock storage does not establish real bucket policy, encryption, isolation or presigned-URL enforcement. The test-only front controller and encrypted bounded job exercise in-flight shutdown; neither is included in the runtime image. Use a separate staging suite to validate actual TLS, SMTP, private-bucket policy and protected downloads.

The final image's explicit source copies and allowlisted context exclude local environment files, Git, instructions/guides, host dependencies, cached configuration, keys, storage, logs and reports. The nonsecret `.env.example` is available only to the test stage, not runtime. Never upload Render secret files under allowlisted source paths. Immutable PHP, Node and Composer base digests are recorded in Dockerfile; rebuild/review image OS advisories as part of release maintenance. No dependency update occurs during build. The `context-audit` target lets reviewers export the exact permitted build context separately.

## Shared Render configuration

Before an approved Blueprint setup, create an environment group named `aether-runtime` in the Render dashboard and populate it with the reviewed values below. The template references this existing group from all three services; it does not create or manage the group. Scope it to the intended environment and do not reuse production secrets in staging.

Render ignores `sync: false` variables inside environment groups, so secret placeholders there do not prompt for or populate values. Keeping one manually populated group ensures web, worker and scheduler receive identical keys and shared-service configuration. See [Render's environment-group restrictions](https://render.com/docs/blueprint-spec#environment-groups) and [group setup instructions](https://render.com/docs/configure-environment-variables#creating-an-environment-group).

| Group setting | Required value |
| --- | --- |
| `APP_ENV` | `production` |
| `APP_DEBUG` | `false` |
| `LOG_CHANNEL` | `stderr` |
| `DB_CONNECTION` | `pgsql` |
| `DB_SSLMODE` | `require` |
| `SESSION_DRIVER` | `database` |
| `SESSION_SECURE_COOKIE` | `true` |
| `CACHE_STORE` | `database` |
| `QUEUE_CONNECTION` | `database` |
| `DB_QUEUE` | `default` |
| `DB_QUEUE_RETRY_AFTER` | `90` |
| `MAIL_MAILER` | `smtp` |
| `AETHER_PRIVATE_DISK` | `private_s3` |
| `AETHER_RETENTION_ENABLED` | `false` |

Supply the environment-specific `APP_URL`, existing approved `APP_KEY`, `PASSPORT_PRIVATE_KEY`, `PASSPORT_PUBLIC_KEY`, `MAIL_HOST`, `MAIL_PORT`, `MAIL_USERNAME`, `MAIL_PASSWORD`, `MAIL_FROM_ADDRESS`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`, `AWS_BUCKET` and `AETHER_STORAGE_PREFIX` in that same group. Use the canonical HTTPS issuer for `APP_URL`. Keep actual values out of source control; do not generate or rotate real keys during setup without separate approval. Any optional trusted-key ring, Passport payload-encryption key, SMTP scheme or S3-compatible endpoint settings also belong to the same reviewed group when applicable.

The template supplies `DB_URL` separately to each service from the same managed database. Do not override it with a different database in the group or a service. Group creation, actual values, resources and activation remain separately approved deployment work; this documentation does not perform that setup.

## Runtime roles

The entrypoint accepts exactly one role: `web` (default), `worker`, `scheduler` or `release`. It checks configuration, discovers packages and creates private config/route/view caches in that instance before execution. It never clears shared cache, generates keys or runs migrations automatically. The `release` role explicitly runs `migrate --force`; use it only for a separately approved target/backup. Worker and scheduler never migrate. Do not mount shared `bootstrap/cache`; runtime caches contain secrets.

Every role needs the same runtime APP_KEY, Passport active pair/trusted key configuration, HTTPS APP_URL/canonical issuer, PostgreSQL DB_URL (not DATABASE_URL), database sessions/cache/queues, SMTP configuration and private_s3 bucket/prefix/credentials. Supply keys using the application's existing PEM environment settings or reviewed runtime secret files. Never use Docker build arguments for secrets or generate replacement production keys on startup. Configure SESSION_SECURE_COOKIE=true, LOG_CHANNEL=stderr, DB_QUEUE=default, DB_QUEUE_RETRY_AFTER=90 and AETHER_RETENTION_ENABLED=false. Preflight validates local configuration/key material without contacting SMTP/S3 or writing records. Supply and validate real provider configuration separately.

Web listens on validated PORT (default 10000, range 1024–65535), serving public only. Source/public/vendor are owned by root and not writable by the runtime UID. Only private runtime cache/storage and scratch locations are writable. Apache forwards Authorization/X-XSRF headers, denies dotfiles and PHP files other than index.php, and suppresses raw access/native diagnostic logs; application errors use the existing safe stderr logger. Review edge/APM logs separately. No proxy trust, CORS, CSP, auth policy, HSTS or issuer change is made by packaging.

`/up` is liveness. `/ready` returns fixed Ready/200 or Unavailable/503 without sessions or diagnostic details. Its SELECT 1 runs in a separate CLI process with a three-second total deadline, two-second connection timeout and one-second statement timeout. Credentials travel on stdin, never arguments. Readiness is not a full dependency check or token-issuance permission.

The worker uses the database/default queue, timeout 60, tries 3, backoff 30 and sleep 3; job-specific limits still apply. Configure the host to restart exited workers, including database outages. The scheduler runs schedule:run once and exits; provision exactly one every-minute UTC scheduler. Existing hourly expiry/deletion work requires a separately approved named environment. Retention remains disabled. Only the designated release owner may migrate.

All roles use SIGTERM. The web PID-1 wrapper translates it to Apache graceful-stop, reaps the child and bounds draining below 120 seconds. Worker directly execs queue:work so PCNTL can finish its current job. Configure maxShutdownDelaySeconds=120 for web/worker. Service deployment is not atomic: coordinate one commit, schema compatibility and web/worker/scheduler restarts. No exactly-once delivery guarantee is implied.

The Render example has manual deployment and region/compute placeholders. Do not activate it before approving resources, costs, domain/proxy trust, TLS, shared secrets/bucket configuration, backup/restore and migration ownership. Git publication, hosted CI changes, deployment and production readiness are separate boundaries.
