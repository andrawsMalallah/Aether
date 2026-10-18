<section class="settings-section developer-integration" aria-labelledby="integration-title">
    <h2 id="integration-title">Connect your service</h2>
    <p>Keep the client secret in your server environment. Use client credentials over trusted HTTPS; this flow has no browser login, callback, consent, ID token or refresh token.</p>
    <p>Before requesting tokens, ask an administrator to approve your API permissions and activate the application. Each API must also explicitly permit this client. A Live status alone does not grant resource access.</p>
    <dl class="developer-integration-settings">
        <div><dt>Token endpoint · POST</dt><dd><code>{{ $integration['token_endpoint'] }}</code></dd></div>
        <div><dt>Authentication</dt><dd><code>client_secret_post</code></dd></div>
        <div><dt>Approved scopes</dt><dd><code>{{ implode(' ', array_keys($application['scopes'])) ?: 'None approved' }}</code></dd></div>
        <div><dt>Revocation endpoint · POST</dt><dd><code>{{ $integration['revocation_endpoint'] }}</code></dd></div>
    </dl>
    <h3>Token request</h3>
    <p>Send a form-encoded POST from your service using these fields. Replace the placeholders in your server configuration; never put secrets into browser code or logs.</p>
    <pre class="developer-urls"><code>grant_type=client_credentials
client_id=YOUR_CLIENT_ID
client_secret=YOUR_CLIENT_SECRET
scope=ADMIN_APPROVED_SCOPES</code></pre>
    <p>Call the approved API with <code>Authorization: Bearer YOUR_ACCESS_TOKEN</code>. Keep tokens private. Obtain a new access token when needed; there is no refresh grant for Machine apps.</p>
    <p>To revoke a token, send a form-encoded POST to the revocation endpoint with <code>client_id</code>, <code>client_secret</code> and <code>token</code>. Secret rotation, suspension and deletion immediately invalidate this application's tokens.</p>
    @include('developer.machine-example')
</section>
