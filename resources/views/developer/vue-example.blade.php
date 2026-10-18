<details>
    <summary>Vue Browser example: sign in, refresh and local logout</summary>
    <p>This Vue 3 / Vite example uses Prism's public-client flow with <code>openid-client 6.8.8</code>. It runs entirely in your separate browser app. It has no client secret, backend or database and does not authorize access to any backend API.</p>
    <h3>1. Prepare your browser app</h3>
    <p>Use an existing Vue 3 / Vite app with Node <code>^22.12.0 || &gt;=24.0.0</code>. Run these commands in that client project, not in the Aether provider:</p>
    <pre class="developer-urls"><code>npm install --save-exact openid-client@6.8.8
npm audit</code></pre>
    <p>Register a Browser application, select <code>openid</code>, <code>profile</code> and <code>email</code>, and save the exact callback <code>http://localhost:5173/auth/callback</code> for local development. This profile example requires all three scopes. Use your verified owner account while Testing. For deployment, replace the origin and callback with your own HTTPS domain.</p>
    <p class="notice">Ask the Aether operator to approve your exact origin before trying the flow. Only the existing local Prism origin is currently configured for local development; this guide grants no new origin access. Other ports, hosts and deployed origins need separate approval. Registration and Go live do not configure CORS.</p>
    <p>In the client app's environment, set the public values below using the settings on this page. Vite exposes all <code>VITE_</code> values to the browser: never add a secret or token. Restart Vite after changing configuration.</p>
    <pre class="developer-urls"><code>VITE_AETHER_ISSUER=&lt;issuer from this page&gt;
VITE_AETHER_CLIENT_ID=&lt;client ID from this page&gt;</code></pre>
    <p>The issuer must use trusted HTTPS. Trust Herd's certificate locally; never disable certificate or ID-token validation. Keep the Vue entry point mounting <code>App.vue</code> as usual. This example uses the app root and reserves <code>/auth/callback</code>; do not mount a second router or analytics scripts that process the callback first. Configure deployed hosting to serve the SPA entry point at that callback path. Use <code>Referrer-Policy: no-referrer</code> and exclude callback query strings and protocol request bodies from access logs, analytics and error reporting.</p>
    <h3>2. Add the client files</h3>
    <p>Save each file below under <code>src/</code>. The auth module stores only a ten-minute, single-use state/nonce/PKCE transaction in per-tab sessionStorage. It clears callback parameters before discovery or token requests. Access, ID and refresh tokens stay inside its closure; the Vue snapshot contains profile fields and a safe message only.</p>
    @foreach(['auth.js', 'App.vue', 'example.css'] as $exampleFilename)
        <h4><code>src/{{ $exampleFilename }}</code></h4>
        <pre class="developer-urls"><code>{{ file_get_contents(resource_path('examples/browser/'.$exampleFilename)) }}</code></pre>
    @endforeach
    <h3>3. Run and check the flow</h3>
    <pre class="developer-urls"><code>npm run dev -- --host localhost --port 5173 --strictPort</code></pre>
    <p>Open <code>http://localhost:5173</code>. Test sign-in, Deny then retry/Allow, Refresh session and Sign out of this app. Check that the callback query is removed, refreshing the page clears the local profile, and a returning sign-in can reuse Aether's session. Sign-out clears local identity even when credential revocation fails and reports unconfirmed cleanup. It does not sign out of Aether or other apps.</p>
    <p>Refresh operations are serialized and replace the token pair together. A refresh failure clears identity and asks for sign-in again. Treat the validated issuer and subject as the account key; never trust email or Vue state as backend authorization. The browser still needs XSS protection and a suitable content security policy; do not use v-html for identity fields or persist tokens in Web Storage.</p>
    <p>Review the page at desktop and 320px widths and use Tab/Enter/Space on the buttons. When the local flow is accepted, deployment still needs an exact HTTPS callback, approved origin, and an explicit Go live action. This example does not publish your app automatically.</p>
    <p>Library reference: <a href="https://github.com/panva/openid-client/tree/v6.8.8">openid-client 6.8.8</a>.</p>
</details>
