<details>
    <summary>Laravel Machine example: request, call an API and revoke</summary>
    <p>This Laravel 13 / PHP 8.3 console example follows Pulse's service flow using Laravel's installed HTTP client. It requests <code>stats:read</code>, reads the approved Waraq aggregate <code>{"notes": 12}</code>, then revokes the temporary access token before printing the total. It needs no new Composer package and does not read individual notes.</p>
    <h3>1. Obtain administrator approval</h3>
    <p>Register a Machine app and save its one-time secret privately. Ask an administrator to approve <code>stats:read</code>, explicitly select the Waraq resource API and activate the app. Testing and Suspended clients cannot request tokens. Live status without the resource permission is insufficient. This guide does not grant scopes, change allowlists or activate your app.</p>
    <p>Ask the operator for the exact approved HTTPS resource URL. Waraq uses <code>https://waraq.test/api/stats</code> locally; do not assume another deployment uses that hostname. This example expects Waraq's notes response, not Pocket's bookmarks response or a generic API schema.</p>
    <h3>2. Configure your separate Laravel service</h3>
    <p>Set these values privately in the client service's environment using the token endpoint's issuer and the client ID above. Never put credentials in command arguments, shell history, browser code, source control or logs. No provider environment changes are required.</p>
    <pre class="developer-urls"><code>AETHER_MACHINE_ISSUER=&lt;approved HTTPS issuer&gt;
AETHER_MACHINE_CLIENT_ID=&lt;your Machine client ID&gt;
AETHER_MACHINE_CLIENT_SECRET=&lt;your private client secret&gt;
AETHER_MACHINE_RESOURCE_URL=&lt;approved HTTPS Waraq stats URL&gt;</code></pre>
    <p>Create <code>config/aether-machine.php</code> and <code>app/Console/Commands/ReadAetherStats.php</code> in that client project. Laravel discovers commands in its standard commands directory. Keep TLS verification enabled; for Herd, trust its CA through PHP's certificate configuration. Exclude HTTP request headers/bodies, command memory and credentials from monitoring; generic errors alone do not configure your telemetry.</p>
    @foreach(['aether-machine.php' => 'config/aether-machine.php', 'ReadAetherStats.php' => 'app/Console/Commands/ReadAetherStats.php'] as $exampleFilename => $destinationPath)
        <h4><code>{{ $destinationPath }}</code></h4>
        <pre class="developer-urls"><code>{{ file_get_contents(resource_path('examples/machine/'.$exampleFilename)) }}</code></pre>
    @endforeach
    <h3>3. Run the command</h3>
    <pre class="developer-urls"><code>php artisan config:clear
php artisan aether:stats</code></pre>
    <p>Run this in the client service, not Aether. A successful command prints only the notes total and cleanup confirmation, never the token. It uses bounded HTTPS requests, refuses redirects, sends the access token only in the Bearer header and attempts cleanup after API or response-validation failures. It does not automatically retry token issuance; after a timeout the outcome may be unknown.</p>
    <p>A token-request failure can mean invalid credentials, Testing/Suspended state, an unapproved scope or an unavailable provider. Resource 401 means the token was rejected, 403 means access was denied and 503 can indicate unavailable introspection; check the operator's safe diagnostics instead of printing response bodies. If cleanup cannot be confirmed, the command fails without printing a report; the token may remain valid until expiry or operator revocation.</p>
    <p>There is no browser login, callback, consent, ID token or refresh token in this flow. Request a new access token for each command run. Aether secret rotation, suspension or deletion invalidates this app's credentials; changing this example's environment never grants API access. Run scheduled/background work through your service's normal scheduler or queue, rather than placing this command's network work in a web request.</p>
    <p>Reference: <a href="https://laravel.com/docs/13.x/http-client">Laravel HTTP client</a>.</p>
</details>
