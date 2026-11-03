<details>
    <summary>Vue Browser example: sign in, refresh and local logout</summary>
    <p>Use this optional Vue 3 / Vite example to add sign-in to your own browser app with <code>openid-client 6.8.8</code>. It shows the user's profile, refreshes the session and signs out locally. It needs no client secret, backend or database. A backend API would still need its own token and permission checks.</p>
    <h3>1. Prepare your browser app</h3>
    <p>Use your Vue 3 / Vite project with Node <code>^22.12.0 || &gt;=24.0.0</code>. Run these commands in that project, not in Aether:</p>
    <pre class="developer-urls"><code>npm install --save-exact openid-client@6.8.8
npm audit</code></pre>
    <p>Register a Browser application and enable <code>openid</code>, <code>profile</code> and <code>email</code>. This profile example requires all three scopes. For the local setup below, save the exact callback <code>http://localhost:5173/auth/callback</code>. Use your verified owner account while Testing.</p>
    <p class="notice">Ask the Aether operator to approve your exact browser origin before testing. An origin is the scheme, hostname and port, such as <code>http://localhost:5173</code>. Approval is required even when the callback is registered; this guide grants no new origin access. Go live does not configure CORS. Use your own HTTPS origin and callback when deploying.</p>
    <p>Set these public values in your app's environment file, then restart Vite. All <code>VITE_</code> values are visible to the browser, so never put a secret or token there.</p>
    <pre class="developer-urls"><code>VITE_AETHER_ISSUER=&lt;issuer from this page&gt;
VITE_AETHER_CLIENT_ID=&lt;client ID from this page&gt;</code></pre>
    <p>Keep Aether's HTTPS certificate and ID-token checks enabled. Trust a local development certificate instead of disabling verification. Keep your usual Vue entry point mounting <code>App.vue</code>; this example handles the app root and <code>/auth/callback</code>.</p>
    <p>On deployed hosting, make the callback path serve your SPA entry point. Let the auth module process that callback before another router or analytics script. Set <code>Referrer-Policy: no-referrer</code> and exclude callback query strings and protocol request bodies from logs, analytics and error reports.</p>
    <h3>2. Add the client files</h3>
    <p>Save the following files under <code>src/</code>. The auth module remembers a sign-in attempt for up to ten minutes in that tab's sessionStorage, then consumes it once and removes callback parameters before making protocol requests. Tokens stay in memory inside the module; the Vue component receives only profile fields and a safe status message.</p>
    @foreach(['auth.js', 'App.vue', 'example.css'] as $exampleFilename)
        <h4><code>src/{{ $exampleFilename }}</code></h4>
        <pre class="developer-urls"><code>{{ file_get_contents(resource_path('examples/browser/'.$exampleFilename)) }}</code></pre>
    @endforeach
    <h3>3. Run and check the flow</h3>
    <pre class="developer-urls"><code>npm run dev -- --host localhost --port 5173 --strictPort</code></pre>
    <p>Open <code>http://localhost:5173</code>. Try sign-in, deny permission and retry, allow permission, refresh the session, then sign out. The callback query should disappear. Reloading the page clears the local profile because tokens are not saved in browser storage.</p>
    <p>Sign-out clears local identity even if token revocation fails, and warns if cleanup is unconfirmed. Aether and other apps stay signed in. Refreshes run one at a time and replace both tokens together; a refresh failure asks for sign-in again.</p>
    <p>Identify users by the validated issuer and subject. Email or Vue state alone must not authorize backend requests. Keep XSS protection and a suitable content security policy; do not use <code>v-html</code> for identity fields or save tokens in Web Storage.</p>
    <p>Check desktop/mobile sizing and Tab, Enter and Space controls. Before other users can sign in, configure the deployed HTTPS callback, obtain origin approval and choose Go live.</p>
    <p>Library reference: <a href="https://github.com/panva/openid-client/tree/v6.8.8">openid-client 6.8.8</a>.</p>
</details>
