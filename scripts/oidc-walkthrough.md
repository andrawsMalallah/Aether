# Local OIDC walkthrough

Use `http://aether.test` with the existing public local walkthrough client. Confirm the normal OIDC migration has run; keep all credentials/tokens in local tooling, never shared logs or shell history.

1. Open `http://aether.test/.well-known/openid-configuration`. Check issuer, authorization/token/userinfo URLs, and `jwks_uri` point to Aether.
2. Open `http://aether.test/.well-known/jwks.json`. The key contains only public JOSE fields (`kty`, `use`, `alg`, `kid`, `n`, `e`), never private RSA parameters.
3. Configure a standard OIDC client with that issuer/discovery URL, the fixture client ID, public client authentication, and exactly `http://localhost:8765/callback`. Enable authorization code + S256 PKCE and request `openid profile email`. Have the client generate and check state/nonce. For HTTP local testing only, opt in to the client's insecure-transport allowance.
4. Follow hosted login and consent. Test Allow/Deny on desktop and a 320px mobile viewport. A session created before this upgrade will require fresh login; 2FA continues to apply when enabled.
5. Let the standard client exchange the code and validate the ID token using JWKS: signature, `kid`, canonical issuer, client audience, expiry, subject, and matching nonce. Never treat the access token as the ID token.
6. Call GET or POST `/oauth/userinfo` using the access token's Bearer header. The subject matches the ID token. Repeat with `openid` alone: name and email are absent. `openid profile` exposes name; `openid email` exposes email and verification state. Private avatars are omitted.
7. Refresh through the client: original `auth_time` and nonce remain unchanged; refreshed identity claims follow granted scopes. Reused refresh credentials fail. Revoke the current token and confirm userinfo returns 401. Browser login alone cannot call userinfo.
8. Check returning-user consent reuse and `prompt=consent`. `prompt=login` requests fresh authentication; `prompt=none` cannot display login/consent UI and returns the corresponding protocol error instead.

Unsupported request features (`max_age`, claims/request objects, request URIs, hints/ACR, non-query response modes) are rejected. This phase proves basic OIDC interoperability; it does not claim full OpenID conformance certification. Browser-origin configuration and permanent demo apps arrive in Phase 5. CORS defaults to no approved origins.

Run `composer check`, `composer audit`, `npm audit`, and `npm run build` before publication. Tests use isolated databases/keys. The temporary discovery-client HTTP verification used a separate SQLite fixture with real login/consent CSRF; it did not modify real account credentials or the provider's signing keys.
