<section class="settings-section developer-integration" aria-labelledby="integration-title">
    <h2 id="integration-title">Connect your Mobile application</h2>
    <p>Let people sign in to your native app with their Aether account. Use a maintained OpenID Connect library that supports authorization code flow with PKCE (S256). This is a public client: it has no client secret.</p>
    <p>A callback is the HTTPS app link that returns someone to your app after sign-in. Scopes are the account information your app requests. An ID token proves the signed-in identity; an access token lets your app request permitted API data.</p>
    @if(in_array($application['status'], ['Suspended', 'Revoked'], true))
        <p class="notice">This application is unavailable. These settings are for reference; sign-in cannot complete while it is suspended or revoked.</p>
    @endif

    <h3>1. Configure your library and app links</h3>
    <p>Use these settings with your library. Register an exact HTTPS app/universal link and configure your platform's app-to-domain association, including its hosted association file. Aether does not configure or verify that association. Custom URI schemes and HTTP callbacks are not supported.</p>
    <dl class="developer-integration-settings">
        <div><dt>Issuer</dt><dd><code>{{ $integration['issuer'] }}</code></dd></div>
        <div><dt>Discovery URL</dt><dd><code>{{ $integration['issuer'] }}/.well-known/openid-configuration</code></dd></div>
        <div><dt>Client ID</dt><dd><code>{{ $application['id'] }}</code></dd></div>
        <div><dt>Authentication</dt><dd><code>none</code> (no client secret)</dd></div>
        <div><dt>Allowed scopes</dt><dd><code>{{ implode(' ', array_keys($application['scopes'])) }}</code></dd></div>
        <div><dt>Registered callbacks</dt><dd><ul>@foreach($application['redirect_uris'] as $callback)<li><code>{{ $callback }}</code></li>@endforeach</ul></dd></div>
    </dl>

    <h3>2. Open sign-in in the system browser</h3>
    <p>Start sign-in through the operating system's external authentication session or system browser. Request only the scopes you need, including <code>openid</code>. Let your library create a fresh, short-lived, single-use transaction for each attempt. Do not use an embedded WebView or collect Aether passwords in your app.</p>

    <h3>3. Complete the callback and validate the account</h3>
    <p>Let your library check the callback and exchange its one-time code. Reject an invalid or reused attempt; denied consent ends the attempt without signing in. Validate the ID token before accepting an identity, and identify accounts by issuer and subject (<code>iss</code> and <code>sub</code>), never email alone.</p>
    <p>If you request UserInfo, send the access token in an <code>Authorization: Bearer</code> header and require its <code>sub</code> to match the validated ID token. APIs must independently validate and authorize access tokens.</p>

    <h3>4. Keep credentials private and test the full flow</h3>
    <p>Keep tokens in memory where possible. Retain credentials only in your platform's secure credential storage, never plain preferences, files, logs, analytics or crash reports. Serialize refresh requests and replace the access and refresh tokens atomically; never reuse an old refresh token. If refreshing fails, start a new sign-in.</p>
    <p>For local logout, revoke the retained token and clear local credentials even if revocation fails. Your app signs out; Aether and other apps remain signed in. Discovery does not advertise a provider logout endpoint.</p>
    <p>While Testing, only you can sign in. After checking the full native flow and domain association, choose Go live to allow other verified users. Callback edits cancel pending codes; suspension or deletion invalidates the application's credentials. Native networking does not require changing Aether's browser CORS configuration.</p>

    <details>
        <summary>Protocol details and endpoints</summary>
        <dl class="developer-integration-settings">
            <div><dt>Authorization · GET</dt><dd><code>{{ $integration['authorization_endpoint'] }}</code></dd></div>
            <div><dt>Token · POST</dt><dd><code>{{ $integration['token_endpoint'] }}</code></dd></div>
            <div><dt>UserInfo · GET</dt><dd><code>{{ $integration['userinfo_endpoint'] }}</code></dd></div>
            <div><dt>Revocation · POST</dt><dd><code>{{ $integration['revocation_endpoint'] }}</code></dd></div>
        </dl>
        <p><strong>Authorization:</strong> generate fresh random <code>state</code>, <code>nonce</code> and a PKCE <code>code_verifier</code> for each attempt. Bind the saved transaction to the initiating app instance, and derive <code>code_challenge</code> using S256. Open the authorization endpoint with <code>response_type=code</code>, <code>client_id</code>, the exact <code>redirect_uri</code>, the requested <code>scope</code> including <code>openid</code>, <code>state</code>, <code>nonce</code>, <code>code_challenge</code> and <code>code_challenge_method=S256</code>. Never include the verifier or tokens in this URL.</p>
        <p><strong>Callback and exchange:</strong> require the exact registered callback and reject missing, mismatched or reused state before processing a code or error. Consume the saved attempt once. From the native app, send a form-encoded POST to the token endpoint with <code>grant_type=authorization_code</code>, <code>client_id</code>, <code>code</code>, the same <code>redirect_uri</code> and the original <code>code_verifier</code>. Send no client secret or HTTP Basic credentials. Keep TLS certificate verification enabled and never retry a consumed code.</p>
        <p><strong>Identity validation:</strong> verify the ID token's RS256 signature using discovery/JWKS, exact issuer, audience, authorized party when applicable, expiry and nonce. Decoding a token is not validation.</p>
        <p><strong>Refresh:</strong> send a form-encoded POST containing <code>grant_type=refresh_token</code>, <code>client_id</code> and the saved <code>refresh_token</code>, without a secret. Serialize refreshes and atomically replace the stored access and refresh tokens.</p>
        <p><strong>Revocation:</strong> send a form-encoded POST with <code>client_id</code> and <code>token</code>, without a secret. Clear local credentials even if the request fails.</p>
        <p>Reference: <a href="https://www.rfc-editor.org/rfc/rfc8252">OAuth 2.0 for Native Apps (RFC 8252)</a>.</p>
    </details>
</section>
