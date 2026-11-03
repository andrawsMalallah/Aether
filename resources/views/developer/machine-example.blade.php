<details>
    <summary>Laravel Machine example: request, call an API and revoke</summary>
    <p>Use this optional Laravel 13 / PHP 8.3 command to call an API from your service. It requests an access token with <code>stats:read</code>, reads a sample count, then revokes the token before printing the result. It uses Laravel's built-in HTTP client, so no extra Composer package is needed.</p>
    <p>For this example, your approved API must return <code>{"count": 12}</code>, where the count is a non-negative integer. This is a sample response format, not an Aether endpoint. If your API returns different data, adapt the response validation and output in the command to match its documented format.</p>
    <h3>1. Obtain administrator approval</h3>
    <p>Save the Machine app's one-time secret privately. Ask an administrator to approve <code>stats:read</code>, give this client access to the intended API and activate the app. Testing and Suspended clients cannot request tokens. Live status alone does not grant API access. This guide does not grant scopes or activate your app.</p>
    <p>Ask the API owner for its approved HTTPS URL, such as <code>https://api.your-app.example/stats</code>. Replace this example hostname with the actual API address. Do not use the token endpoint as the resource URL.</p>
    <h3>2. Configure your separate Laravel service</h3>
    <p>Set these values in your service's private environment file. Copy the issuer and client ID from this page and use your saved secret. Keep credentials out of command arguments, shell history, browser code, source control and logs.</p>
    <pre class="developer-urls"><code>AETHER_MACHINE_ISSUER=&lt;approved HTTPS issuer&gt;
AETHER_MACHINE_CLIENT_ID=&lt;your Machine client ID&gt;
AETHER_MACHINE_CLIENT_SECRET=&lt;your private client secret&gt;
AETHER_MACHINE_RESOURCE_URL=&lt;approved HTTPS API URL&gt;</code></pre>
    <p>Create the two files below in your service. Laravel finds commands in <code>app/Console/Commands/</code> automatically. Keep HTTPS certificate checks enabled; trust development certificates in PHP instead of disabling verification. Exclude HTTP credentials, request bodies and command memory from monitoring as well as logs.</p>
    @foreach(['aether-machine.php' => 'config/aether-machine.php', 'ReadAetherStats.php' => 'app/Console/Commands/ReadAetherStats.php'] as $exampleFilename => $destinationPath)
        <h4><code>{{ $destinationPath }}</code></h4>
        <pre class="developer-urls"><code>{{ file_get_contents(resource_path('examples/machine/'.$exampleFilename)) }}</code></pre>
    @endforeach
    <h3>3. Run the command</h3>
    <pre class="developer-urls"><code>php artisan config:clear
php artisan aether:stats</code></pre>
    <p>Run these commands in your service, not Aether. Success prints <code>Count: 12. Temporary token revoked.</code> for the sample response. The command uses timeouts, refuses redirects and sends the token only in the Bearer header. It also tries to revoke a received token if the API call or response check fails.</p>
    <h3>If something goes wrong</h3>
    <ul>
        <li>Token request failed: check the credentials, Live status, approved scope and Aether availability. The command does not automatically retry token issuance; a timeout can leave its outcome unknown.</li>
        <li>API returned 401: its token check failed. API returned 403: this client lacks permission. A 503 may mean a required service is unavailable.</li>
        <li>Cleanup failed: no result is printed. Ask the operator to revoke the credentials, or wait for token expiry. Do not print tokens or upstream response bodies to investigate.</li>
    </ul>
    <p>Machine apps do not sign in a user and receive no ID or refresh token. This command requests a new access token each time it runs. Secret rotation, suspension or deletion invalidates this app's credentials. Changing environment values cannot grant access. Run recurring work through your service's scheduler or queue, rather than inside a web request.</p>
    <p>Reference: <a href="https://laravel.com/docs/13.x/http-client">Laravel HTTP client</a>.</p>
</details>
