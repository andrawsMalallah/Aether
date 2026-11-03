<section class="settings-section developer-integration" aria-labelledby="integration-title">
    <h2 id="integration-title">Connect your service</h2>
    <p>Use this Machine application when a server or background service needs to call an API without signing in a person. Your service exchanges its client ID and secret for an access token, then sends that token to an approved API.</p>
    <p>Scopes describe the API permissions your service can request. An access token carries those permissions; it does not identify a signed-in user. This flow has no browser login, callback, consent, ID token or refresh token.</p>

    <h3>1. Get API access approved</h3>
    <p>Before requesting tokens, ask an administrator to approve your API permissions, authorize access to the required resource APIs and activate the application. Each API must explicitly permit this client. A Live status alone does not grant resource access.</p>
    <dl class="developer-integration-settings">
        <div><dt>Client ID</dt><dd><code>{{ $application['id'] }}</code></dd></div>
        <div><dt>Token endpoint · POST</dt><dd><code>{{ $integration['token_endpoint'] }}</code></dd></div>
        <div><dt>Authentication</dt><dd><code>client_secret_post</code></dd></div>
        <div><dt>Approved scopes</dt><dd><code>{{ implode(' ', array_keys($application['scopes'])) ?: 'None approved' }}</code></dd></div>
        <div><dt>Revocation endpoint · POST</dt><dd><code>{{ $integration['revocation_endpoint'] }}</code></dd></div>
    </dl>

    <h3>2. Configure credentials on your server</h3>
    <p>Keep the client secret in your server environment, outside source control. Never put secrets or tokens in browser code, URLs, logs or error reports. Use trusted HTTPS and keep TLS certificate verification enabled.</p>

    <h3>3. Request a token and call the API</h3>
    <p>Send a form-encoded POST from your service to the token endpoint. Include your client ID, secret and only administrator-approved scopes. The example below shows the request fields and a protected API call.</p>
    <p>Send the returned token to the approved API as <code>Authorization: Bearer YOUR_ACCESS_TOKEN</code>. Keep it private and request a new access token when needed; Machine apps do not use refresh tokens.</p>

    <h3>4. Revoke credentials when they are no longer needed</h3>
    <p>Revoke a token through the revocation endpoint and remove it from your service. Secret rotation, suspension and deletion immediately invalidate this application's tokens. These operations do not sign out Aether users or sessions in other applications.</p>

    <details>
        <summary>Token request and revocation fields</summary>
        <p>Authenticate using <code>client_secret_post</code>: send credentials in the form body, never the URL. Use <code>Content-Type: application/x-www-form-urlencoded</code> and <code>grant_type=client_credentials</code>.</p>
        <pre class="developer-urls"><code>grant_type=client_credentials
client_id=YOUR_CLIENT_ID
client_secret=YOUR_CLIENT_SECRET
scope=ADMIN_APPROVED_SCOPES</code></pre>
        <p>To revoke a token, send a form-encoded POST to the revocation endpoint with <code>client_id</code>, <code>client_secret</code> and <code>token</code>.</p>
    </details>

    @include('developer.machine-example')
</section>
