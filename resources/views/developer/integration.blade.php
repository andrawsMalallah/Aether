<section class="settings-section developer-integration" aria-labelledby="integration-title">
    <h2 id="integration-title">Connect your application</h2>
    <p>Use an OpenID Connect client library on your server with authorization code flow and PKCE (S256). Keep your client secret in your server environment, outside browser code and source control.</p>
    @if(in_array($application['status'], ['Suspended', 'Revoked'], true))
        <p class="notice">This application is unavailable. These settings are for reference; sign-in cannot complete while it is suspended or revoked.</p>
    @endif
    <h3>1. Configure your client</h3>
    <dl class="developer-integration-settings">
        <div><dt>Issuer</dt><dd><code>{{ $integration['issuer'] }}</code></dd></div>
        <div><dt>Discovery URL</dt><dd><code>{{ $integration['issuer'] }}/.well-known/openid-configuration</code></dd></div>
        <div><dt>Client ID</dt><dd><code>{{ $application['id'] }}</code></dd></div>
        <div><dt>Allowed scopes</dt><dd><code>{{ implode(' ', array_intersect(array_keys($application['scopes']), ['openid', 'profile', 'email'])) }}</code></dd></div>
        <div><dt>Registered callbacks</dt><dd><ul>@foreach($application['redirect_uris'] as $callback)<li><code>{{ $callback }}</code></li>@endforeach</ul></dd></div>
        <div><dt>Authorization · GET</dt><dd><code>{{ $integration['authorization_endpoint'] }}</code></dd></div>
        <div><dt>Token · POST</dt><dd><code>{{ $integration['token_endpoint'] }}</code></dd></div>
        <div><dt>UserInfo · GET</dt><dd><code>{{ $integration['userinfo_endpoint'] }}</code></dd></div>
        <div><dt>Signing keys · GET</dt><dd><code>{{ $integration['jwks_uri'] }}</code></dd></div>
        <div><dt>Revocation · POST</dt><dd><code>{{ $integration['revocation_endpoint'] }}</code></dd></div>
    </dl>
    <p>Select one registered callback and send it exactly as saved, including its path, port, query and trailing slash. Request only the scopes your application needs, including <code>openid</code>. Use HTTPS; HTTP callbacks are limited to literal localhost and loopback development addresses.</p>
    <h3>2. Start sign-in</h3>
    <p>For each attempt, let your library generate fresh random <code>state</code>, <code>nonce</code> and a PKCE <code>code_verifier</code>. Store them in a short-lived, single-use server session tied to the initiating browser. Derive <code>code_challenge</code> using S256.</p>
    <p>Redirect the browser to the authorization endpoint with <code>response_type=code</code>, <code>client_id</code>, the exact <code>redirect_uri</code>, space-separated <code>scope</code>, <code>state</code>, <code>nonce</code>, <code>code_challenge</code> and <code>code_challenge_method=S256</code>. Never include your secret or verifier in this URL.</p>
    <h3>3. Handle the callback</h3>
    <p>Reject missing, mismatched or reused state before processing a code or error. If consent is denied, end the attempt without creating a signed-in session. Consume the saved attempt once; do not retry a code exchange with the same code.</p>
    <p>From your server, POST a form-encoded token request with <code>grant_type=authorization_code</code>, <code>code</code>, the same <code>redirect_uri</code> and the original <code>code_verifier</code>. Authenticate using your client ID and secret through HTTP Basic authentication or form fields, never a query string. Keep TLS certificate verification enabled.</p>
    <h3>4. Validate the identity</h3>
    <p>Use your library to verify the ID token's RS256 signature against the discovery signing keys, exact issuer, audience (your client ID), authorized party when applicable, expiry and nonce. Decoding a token alone does not validate it. Identify local accounts by the pair <code>iss</code> and <code>sub</code>, never by email alone, then regenerate your local session ID.</p>
    <p>If you need UserInfo, send the access token only in an <code>Authorization: Bearer</code> header and require its <code>sub</code> to match the validated ID token. Profile and email claims depend on the granted scopes.</p>
    <h3>5. Refresh and sign out</h3>
    <p>Store retained tokens encrypted on your server. To refresh, authenticate your client and POST <code>grant_type=refresh_token</code> with the saved <code>refresh_token</code> to the token endpoint. Serialize refreshes and atomically replace the stored access and refresh tokens with the returned pair. Do not reuse an old refresh token; if refresh fails, start a new sign-in.</p>
    <p>For local logout, end your application's session and revoke its retained credentials with an authenticated, form-encoded POST to the revocation endpoint containing <code>token</code>. Clear local credentials even if revocation fails and queue secure cleanup. This ends your app's session; Aether and other apps stay signed in. There is no provider logout endpoint advertised in discovery.</p>
    <p>Never put passwords, secrets, authorization codes or tokens in logs, error reports or browser storage. Secret regeneration invalidates this app's existing access tokens, refresh tokens and pending codes immediately. Changing callbacks cancels pending codes; removing scopes can require signing in again.</p>
    <p>While Testing, only you can sign in through this app. After checking the full flow, use Go live to allow other verified users; consent and PKCE still apply.</p>
    <p>Protocol references: <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core</a> and <a href="https://www.rfc-editor.org/rfc/rfc7636">PKCE (RFC 7636)</a>.</p>
</section>
