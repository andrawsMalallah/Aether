# Local OAuth2 walkthrough

Use `http://aether.test` and the public client created by `OAuthTestClientSeeder`. This walkthrough exercises the OAuth2 foundation; see [oidc-walkthrough.md](oidc-walkthrough.md) for ID tokens, discovery, JWKS, and userinfo. Do not connect a production app yet.

## Preparation

Confirm the database is your local `aether` database. Run normal `php artisan migrate`, generate a new pair with `php artisan passport:keys` only if none exists, and run `php artisan db:seed --class=OAuthTestClientSeeder`. Find the fixture's non-secret UUID through your local database viewer. Never print private keys, passwords, client secrets, authorization codes, or tokens into shell output/history/logs.

In Postman (local values only; do not sync/share credentials), create a temporary OAuth2 authorization-code + PKCE configuration:

- Authorization URL: `http://aether.test/oauth/authorize`
- Access-token URL: `http://aether.test/oauth/token`
- Callback URL: exactly `http://localhost:8765/callback`
- Client ID: the fixture UUID
- Client secret: empty (public client)
- PKCE challenge method: S256
- Scope: `openid profile email`
- State: a fresh unpredictable value; the client must verify its returned value

Use a local callback listener/script if your API tool cannot receive this exact callback. Keep the verifier, state, returned code, and tokens in memory. PKCE's verifier/challenge generation and state verification belong to the client library; do not construct a custom token format.

## Flow and checks

1. Open the authorization request in a browser while signed out. Sign in to an email-verified account; complete 2FA if enabled. Confirm the browser returns to the consent page.
2. On desktop and at 320px, check the application name, signed-in email, scope descriptions, Terms/Privacy links, and keyboard focus on Allow/Deny.
3. Deny. Verify the callback receives `error=access_denied` with the original state and no code. Retry and Allow; verify state, then exchange the returned code immediately with the original verifier and exact redirect URI.
4. Exchange body: `grant_type=authorization_code`, `client_id`, `code`, `code_verifier`, `redirect_uri`. Expect Bearer access token, `expires_in=3600`, and refresh token. Never send these credentials in URLs.
5. Refresh body: `grant_type=refresh_token`, `client_id`, `refresh_token`. Expect a new pair. Repeat the original refresh request; expect HTTP 400 / `invalid_grant` and a `refresh.replayed` audit record.
6. Repeat the original code exchange. Expect HTTP 400 / `invalid_grant`. All token pairs descended from that code must now be revoked. Start a fresh authorization for subsequent checks.
7. Repeat authorization for the same scopes; no consent prompt should appear. Add `prompt=consent` to force a prompt. To test expansion, grant only `openid` with a fresh user/client first, then request `openid email`.
8. Try an unregistered callback or different loopback port: error stays at Aether, with no redirect. Try missing PKCE, `plain`, an incorrect verifier, and a code older than one minute: all rejected.
9. Revoke body: `client_id`, `token` (access or refresh), optional `token_type_hint`. Expect empty HTTP 200; the associated access/refresh pair no longer works. Unknown tokens also return empty 200. A different client cannot revoke this client's token.
10. For a confidential web/M2M fixture, use HTTP Basic authentication or body credentials, never both. M2M uses `grant_type=client_credentials` and allowed scopes; it returns no refresh token. Create these fixtures through trusted local application code, not an HTTP management endpoint. Secrets remain local and are not logged.

Database audit entries store only event/client/user IDs. Hosted CI is verified after an explicitly authorized publication. The current local seeder is intentionally not included in `DatabaseSeeder`.
