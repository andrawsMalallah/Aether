<section class="settings-section developer-integration" aria-labelledby="integration-title">
    <h2 id="integration-title">Connect your Mobile application</h2>
    <p>Use a maintained native OpenID Connect library with authorization code flow and PKCE (S256). This public client has no secret; use client authentication method <code>none</code>. Never embed a shared secret in your app.</p>
    @if(in_array($application['status'], ['Suspended', 'Revoked'], true))
        <p class="notice">This application is unavailable. These settings are for reference; sign-in cannot complete while it is suspended or revoked.</p>
    @endif
    <h3>1. Configure your app links</h3>
    <p>Register exact HTTPS app/universal links for your callbacks. Configure your platform's app-to-domain association and host its required association file. Aether validates the callback URL, but does not verify or configure your platform association. Custom URI schemes and HTTP callbacks are not supported in this Mobile slice.</p>
    <dl class="developer-integration-settings">
        <div><dt>Issuer</dt><dd><code>{{ $integration['issuer'] }}</code></dd></div>
        <div><dt>Discovery URL</dt><dd><code>{{ $integration['issuer'] }}/.well-known/openid-configuration</code></dd></div>
        <div><dt>Client ID</dt><dd><code>{{ $application['id'] }}</code></dd></div>
        <div><dt>Allowed scopes</dt><dd><code>{{ implode(' ', array_keys($application['scopes'])) }}</code></dd></div>
        <div><dt>Registered callbacks</dt><dd><ul>@foreach($application['redirect_uris'] as $callback)<li><code>{{ $callback }}</code></li>@endforeach</ul></dd></div>
        <div><dt>Authorization · GET</dt><dd><code>{{ $integration['authorization_endpoint'] }}</code></dd></div>
        <div><dt>Token · POST</dt><dd><code>{{ $integration['token_endpoint'] }}</code></dd></div>
        <div><dt>UserInfo · GET</dt><dd><code>{{ $integration['userinfo_endpoint'] }}</code></dd></div>
        <div><dt>Revocation · POST</dt><dd><code>{{ $integration['revocation_endpoint'] }}</code></dd></div>
    </dl>
    <h3>2. Start sign-in in the system browser</h3>
    <p>Use the operating system's external authentication session or system browser. Do not collect Aether passwords in your app or use an embedded WebView for sign-in.</p>
    <p>Let your library generate fresh random <code>state</code>, <code>nonce</code> and a PKCE <code>code_verifier</code> for each attempt. Keep them in a short-lived, single-use transaction bound to the initiating app instance. Derive the <code>code_challenge</code> using S256.</p>
    <p>Open the authorization endpoint with <code>response_type=code</code>, <code>client_id</code>, the exact <code>redirect_uri</code>, the requested <code>scope</code> including <code>openid</code>, <code>state</code>, <code>nonce</code>, <code>code_challenge</code> and <code>code_challenge_method=S256</code>. Never put the verifier or tokens in this URL.</p>
    <h3>3. Handle the app callback</h3>
    <p>Require the exact registered callback and reject missing, mismatched or reused state before processing a code or error. Consume the saved attempt once. Denied consent ends the attempt without signing in.</p>
    <p>From the native app, send a form-encoded POST to the token endpoint with <code>grant_type=authorization_code</code>, <code>client_id</code>, <code>code</code>, the same <code>redirect_uri</code> and the original <code>code_verifier</code>. Send no client secret or HTTP Basic credentials. Keep TLS certificate verification enabled and never retry a consumed code.</p>
    <h3>4. Validate and retain the identity</h3>
    <p>Use your library to validate the ID token's RS256 signature with discovery/JWKS, exact issuer, audience, authorized party when applicable, expiry and nonce. Identify an account by <code>iss</code> and <code>sub</code>, never email alone. Decoding a token is not validation.</p>
    <p>For UserInfo, send the access token only in an <code>Authorization: Bearer</code> header and require its <code>sub</code> to match the validated ID token. Keep tokens in memory where possible; retain credentials only in your platform's secure credential storage. Never store them in plain preferences, files, logs, analytics or crash reports. APIs must independently validate and authorize access tokens.</p>
    <h3>5. Refresh and sign out</h3>
    <p>Refresh with a form-encoded POST containing <code>grant_type=refresh_token</code>, <code>client_id</code> and the saved <code>refresh_token</code>, without a secret. Serialize refreshes and atomically replace the stored access and refresh tokens. Never reuse an old refresh token; start a new sign-in if refresh fails.</p>
    <p>For local logout, POST <code>client_id</code> and <code>token</code> to the revocation endpoint, then clear local credentials even if revocation fails. This ends your app's session; Aether and other apps remain signed in. Discovery does not advertise a provider logout endpoint.</p>
    <p>While Testing, only you can sign in. After validating the native flow and domain association, choose Go live to allow other verified users. Callback edits cancel pending codes; suspension or deletion invalidates the application's credentials. Native networking does not require changing Aether's browser CORS configuration.</p>
    <p>Reference: <a href="https://www.rfc-editor.org/rfc/rfc8252">OAuth 2.0 for Native Apps (RFC 8252)</a>.</p>
</section>
