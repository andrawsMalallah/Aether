<section class="settings-section developer-integration" aria-labelledby="integration-title">
    <h2 id="integration-title">Connect your application</h2>
    <p>Your app sends people to Aether to sign in. Aether sends them back to your app, where your OpenID Connect library checks the result and starts your app's session.</p>
    @if($application['confidential'])
        <p>This is a Web application. Run the sign-in flow on your server and keep the client secret in its environment, outside browser code and source control.</p>
    @else
        <p>This is a public Browser application. Run the flow with a maintained browser OpenID Connect library. It has no client secret; never add one.</p>
        <p class="notice">Before connecting, ask the Aether operator to allow your exact browser origin: its scheme, host and port. Saving a callback or choosing Go live does not enable cross-origin requests.</p>
    @endif
    @if(in_array($application['status'], ['Suspended', 'Revoked'], true))
        <p class="notice">This application is unavailable. These settings are for reference; sign-in cannot complete while it is suspended or revoked.</p>
    @endif
    <h3>1. Copy your app's settings</h3>
    <p>Give these values to your OpenID Connect library:</p>
    <dl class="developer-integration-settings">
        <div><dt>Issuer — the Aether server your app trusts</dt><dd><code>{{ $integration['issuer'] }}</code></dd></div>
        <div><dt>Discovery URL — where your library finds Aether's endpoints and signing keys</dt><dd><code>{{ $integration['issuer'] }}/.well-known/openid-configuration</code></dd></div>
        <div><dt>Client ID — your app's identifier</dt><dd><code>{{ $application['id'] }}</code></dd></div>
        <div><dt>Allowed scopes — the account details your app may request</dt><dd><code>{{ implode(' ', array_intersect(array_keys($application['scopes']), ['openid', 'profile', 'email'])) }}</code></dd></div>
        <div><dt>Registered callbacks — where Aether may return the browser after sign-in</dt><dd><ul>@foreach($application['redirect_uris'] as $callback)<li><code>{{ $callback }}</code></li>@endforeach</ul></dd></div>
    </dl>
    <p>Choose one registered callback and use it exactly as saved, including its path, port, query and trailing slash. Use HTTPS; HTTP callbacks are limited to literal localhost and loopback development addresses.</p>
    <p>Always request <code>openid</code>. Add <code>profile</code> or <code>email</code> only if your app needs them and they appear in its allowed scopes.</p>
    <h3>2. Add sign-in</h3>
    <p>Configure your library to use authorization code flow and PKCE (S256). Your sign-in button should start a fresh sign-in attempt and redirect the browser to Aether.</p>
    <h3>3. Finish sign-in at the callback</h3>
    <p>Let your library check the saved attempt, exchange the returned code and validate the ID token before treating anyone as signed in. If the person denies consent or a check fails, stop the attempt.</p>
    <p>Match accounts using the validated issuer and subject: <code>iss</code> and <code>sub</code>. Never link an existing account by email alone.</p>
    @if($application['confidential'])
        <p>After validation, start your app's local session and regenerate its session ID. Store any retained tokens encrypted on your server.</p>
    @else
        <p>Keep access, ID and refresh tokens in memory, not localStorage, sessionStorage or other persistent browser storage. Start a new sign-in after a reload loses them. A backend API must independently validate and authorize access tokens; browser state alone does not authorize server data.</p>
    @endif
    <h3>4. Handle refresh and sign-out</h3>
    <p>If you use refresh tokens, allow only one refresh at a time and replace the access and refresh tokens together. Never reuse an old refresh token. If refresh fails, start a new sign-in.</p>
    <p>Signing out should clear your app's session and credentials and revoke its retained tokens. Aether and other apps stay signed in; Aether does not advertise a provider logout endpoint.</p>
    <h3>5. Test before going live</h3>
    <p>While Testing, only you can sign in through this app. Check sign-in, denied consent, expired sessions and sign-out. Then use Go live to allow other verified users; consent and PKCE still apply.</p>
    <p>Changing callbacks cancels pending codes; removing scopes can require signing in again. Suspension or permanent deletion blocks new sign-in and invalidates this app's credentials.</p>
    <details>
        <summary>Protocol requirements and endpoint reference</summary>
        <p>Use these requirements to check your library's configuration. The examples below show one way to implement them.</p>
        <h3>Keep each sign-in attempt separate</h3>
        <p>Generate fresh random <code>state</code>, <code>nonce</code> and a PKCE <code>code_verifier</code> for every attempt. Derive <code>code_challenge</code> using S256.</p>
        @if($application['confidential'])
            <p>Store the attempt in a short-lived, single-use server session tied to the initiating browser.</p>
        @else
            <p>Use a short-lived, single-use transaction store tied to the initiating browser tab so the attempt survives the login redirect. Remove the saved transaction after the callback. This temporary transaction is separate from tokens, which must stay in memory.</p>
        @endif
        <p>Send <code>response_type=code</code>, <code>client_id</code>, the exact <code>redirect_uri</code>, space-separated <code>scope</code>, <code>state</code>, <code>nonce</code>, <code>code_challenge</code> and <code>code_challenge_method=S256</code> to the authorization endpoint. Never include your secret or verifier in this URL.</p>
        <p>Reject missing, mismatched or reused state before processing a code or error. Consume the saved attempt once; do not retry an exchange with the same code.</p>
        <h3>Exchange the code</h3>
        <p>POST a form-encoded token request with <code>grant_type=authorization_code</code>, <code>code</code>, the same <code>redirect_uri</code> and the original <code>code_verifier</code>. Keep TLS certificate verification enabled.</p>
        @if($application['confidential'])
            <p>Make the request from your server. Authenticate using your client ID and secret through HTTP Basic authentication or form fields, never a query string.</p>
        @else
            <p>Make the request from the browser with <code>client_id</code>. Use client authentication method <code>none</code>: no secret or HTTP Basic header. Send cross-origin requests without cookies. Remove the code from the callback URL after processing. PKCE does not replace XSS protection against injected scripts.</p>
        @endif
        <h3>Check the identity and account details</h3>
        <p>Your library must verify the ID token's RS256 signature against the discovery signing keys, exact issuer (<code>iss</code>), audience (<code>aud</code>, your client ID), authorized party (<code>azp</code>) when applicable, expiry and saved nonce. Decoding a token alone does not validate it.</p>
        <p>If you need UserInfo, send the access token only in an <code>Authorization: Bearer</code> header. Require its <code>sub</code> to match the validated ID token. Profile and email claims depend on the granted scopes.</p>
        <h3>Refresh and revoke tokens</h3>
        <p>For refresh, POST <code>grant_type=refresh_token</code> and the saved <code>refresh_token</code> to the token endpoint. Serialize refreshes and atomically replace the access and refresh tokens with the returned pair.</p>
        @if($application['confidential'])
            <p>Authenticate refresh requests using your client ID and secret. For local logout, end your app's session and send an authenticated, form-encoded POST to the revocation endpoint containing <code>token</code>. Clear local credentials even if revocation fails and queue secure cleanup.</p>
            <p>Secret regeneration invalidates this app's existing access tokens, refresh tokens and pending codes immediately.</p>
        @else
            <p>Include <code>client_id</code> in refresh requests, without a secret. For local logout, POST a form-encoded request to the revocation endpoint with <code>client_id</code> and <code>token</code>, without a secret or cookies. Clear all in-memory credentials even if revocation fails.</p>
        @endif
        <p>Never put passwords, secrets, authorization codes or tokens in logs, error reports or persistent browser storage.</p>
        <h3>Endpoints</h3>
        <dl class="developer-integration-settings">
            <div><dt>Authorization · GET</dt><dd><code>{{ $integration['authorization_endpoint'] }}</code></dd></div>
            <div><dt>Token · POST</dt><dd><code>{{ $integration['token_endpoint'] }}</code></dd></div>
            <div><dt>UserInfo · GET</dt><dd><code>{{ $integration['userinfo_endpoint'] }}</code></dd></div>
            <div><dt>Signing keys · GET</dt><dd><code>{{ $integration['jwks_uri'] }}</code></dd></div>
            <div><dt>Revocation · POST</dt><dd><code>{{ $integration['revocation_endpoint'] }}</code></dd></div>
        </dl>
        <p>Protocol references: <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core</a> and <a href="https://www.rfc-editor.org/rfc/rfc7636">PKCE (RFC 7636)</a>.</p>
    </details>
    @if($application['confidential'])
        @include('developer.laravel-example')
    @else
        @include('developer.vue-example')
    @endif
</section>
