<details>
    <summary>Laravel example: sign in and local logout</summary>
    <p>Use this optional example to try Aether sign-in in your own Laravel 13 / PHP 8.3 app. It uses Socialite and an OpenID Connect driver to check the sign-in response, then keeps the validated identity in a server session for fifteen minutes.</p>
    <p>This example does not create local users, sign them into Laravel's auth guard or refresh tokens. In a full app, connect the validated issuer and subject to a local user, then apply your normal access rules. Do not link accounts by email alone.</p>
    <h3>1. Prepare your client app</h3>
    <p>Run these commands in your app's project folder, not in Aether:</p>
    <pre class="developer-urls"><code>composer require "laravel/socialite:^5.31" "socialiteproviders/openidconnect:^1.0.1"
composer audit</code></pre>
    <p>Replace <code>your-app.example</code> with your HTTPS domain. Save <code>https://your-app.example/auth/aether/callback</code> as a callback on this Web application and enable <code>openid</code>. Add <code>profile</code> or <code>email</code> only if you need them. While the app is Testing, use its verified owner account.</p>
    <p>Copy the settings below into your app's private environment file. Use the issuer and client ID shown above, plus the secret you saved when registering the app. Keep that file out of source control.</p>
    <p>This example needs server-side sessions and a background queue for token cleanup. Configure the database tables or other storage those services need using your app's normal setup. Do not use cookie sessions or the sync queue. Keep HTTPS certificate checks enabled; trust your local development certificate in PHP rather than disabling verification.</p>
    <pre class="developer-urls"><code>AETHER_ISSUER=&lt;issuer from this page&gt;
AETHER_CLIENT_ID=&lt;client ID from this page&gt;
AETHER_CLIENT_SECRET=&lt;your private client secret&gt;
AETHER_REDIRECT_URI=https://your-app.example/auth/aether/callback
SESSION_DRIVER=database
SESSION_SECURE_COOKIE=true
SESSION_SAME_SITE=lax
QUEUE_CONNECTION=database</code></pre>
    <p>Create <code>config/oidc.php</code> with the following settings. The package registers the <code>oidc_aether</code> driver automatically. Keep its requested scopes within the permissions enabled for your app.</p>
    @php
        $configurationExample = <<<'PHP'
<?php

return ['connections' => ['aether' => [
    'base_url' => env('AETHER_ISSUER'),
    'client_id' => env('AETHER_CLIENT_ID'),
    'client_secret' => env('AETHER_CLIENT_SECRET'),
    'redirect' => env('AETHER_REDIRECT_URI'),
    'scopes' => ['openid'],
    'jwt_algorithm' => 'RS256',
    'verify_jwt' => true,
    'use_nonce' => true,
    'http_timeout' => 10,
    'http_connect_timeout' => 5,
]]];
PHP;
    @endphp
    <pre class="developer-urls"><code>{{ $configurationExample }}</code></pre>
    <h3>2. Check the return from Aether</h3>
    <p>Create <code>app/Http/Requests/AetherExampleCallbackRequest.php</code>. This checks the callback fields and shows a safe error if they are invalid. It does not save the sign-in code or state as old form input.</p>
    @php
        $requestExample = <<<'PHP'
<?php

namespace App\Http\Requests;

use Illuminate\Contracts\Validation\Validator;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Http\Exceptions\HttpResponseException;

class AetherExampleCallbackRequest extends FormRequest
{
    public function authorize(): bool
    {
        return true;
    }

    public function rules(): array
    {
        return [
            'state' => ['required', 'string', 'max:256'],
            'code' => ['required_without:error', 'string', 'max:8192'],
            'error' => ['nullable', 'string', 'max:100'],
        ];
    }

    protected function failedValidation(Validator $validator): never
    {
        $this->session()->forget(['state', 'code_verifier', 'openidconnect_nonce', 'aether_attempt_expires']);
        throw new HttpResponseException(
            redirect('/aether-example')->withErrors(['login' => 'Sign-in was not completed. Please try again.'])
        );
    }
}
PHP;
    @endphp
    <pre class="developer-urls"><code>{{ $requestExample }}</code></pre>
    <h3>3. Clean up tokens in the background</h3>
    <p>Create <code>app/Jobs/RevokeAetherExampleToken.php</code>. This example only needs the user's identity, so it queues token revocation after validating sign-in. Aether also revokes the refresh token associated with that access token; neither is kept in the session.</p>
    <p>The job is encrypted because it carries credentials. Keep credentials, callback queries and job arguments out of logs and monitoring. Check failed jobs and retry cleanup after fixing any connection problem.</p>
    @php
        $jobExample = <<<'PHP'
<?php

namespace App\Jobs;

use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Support\Facades\Http;
use RuntimeException;
use Throwable;

class RevokeAetherExampleToken implements ShouldBeEncrypted, ShouldQueue
{
    use Queueable;

    public int $tries = 5;
    public int $backoff = 60;

    public function __construct(private string $accessToken) {}

    public function handle(): void
    {
        try {
            $response = Http::asForm()->connectTimeout(5)->timeout(10)
                ->withOptions(['allow_redirects' => false])
                ->post(rtrim(config('oidc.connections.aether.base_url'), '/').'/oauth/revoke', [
                    'client_id' => config('oidc.connections.aether.client_id'),
                    'client_secret' => config('oidc.connections.aether.client_secret'),
                    'token' => $this->accessToken,
                    'token_type_hint' => 'access_token',
                ]);
            if ($response->successful()) {
                return;
            }
        } catch (Throwable) {
            // HTTP exceptions can contain credentials; do not retain their context.
        }

        throw new RuntimeException('Aether credential cleanup is unavailable.');
    }
}
PHP;
    @endphp
    <pre class="developer-urls"><code>{{ $jobExample }}</code></pre>
    <h3>4. Add the controller and routes</h3>
    <p>Create <code>app/Http/Controllers/AetherExampleController.php</code>. It starts sign-in, handles the callback and saves only the validated identity. Keep the library's session, PKCE, nonce and token-signature checks enabled; do not use <code>stateless()</code>.</p>
    @php
        $controllerExample = <<<'PHP'
<?php

namespace App\Http\Controllers;

use App\Http\Requests\AetherExampleCallbackRequest;
use App\Jobs\RevokeAetherExampleToken;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\View\View;
use Laravel\Socialite\Facades\Socialite;
use RuntimeException;
use Throwable;

class AetherExampleController extends Controller
{
    public function show(Request $request): View
    {
        $identity = $request->session()->get('aether_example');
        if (! is_array($identity) || ($identity['expires_at'] ?? 0) <= time()) {
            $request->session()->forget('aether_example');
            $identity = null;
        }

        return view('aether-example', ['identity' => $identity]);
    }

    public function redirect(Request $request): RedirectResponse
    {
        $request->session()->put('aether_attempt_expires', time() + 300);
        try {
            return Socialite::driver('oidc_aether')->redirect();
        } catch (Throwable) {
            $request->session()->forget(['state', 'code_verifier', 'openidconnect_nonce', 'aether_attempt_expires']);

            return redirect('/aether-example')->withErrors(['login' => 'Sign-in is unavailable. Please try again.']);
        }
    }

    public function callback(AetherExampleCallbackRequest $request): RedirectResponse
    {
        try {
            $expiresAt = $request->session()->pull('aether_attempt_expires', 0);
            if ($request->filled('error') || $expiresAt <= time()) {
                throw new RuntimeException('Sign-in was not completed.');
            }

            $identity = Socialite::driver('oidc_aether')->user();
            $claims = $identity->getRaw();
            $issuer = config('oidc.connections.aether.base_url');
            $subject = $claims['sub'] ?? null;
            if (($claims['iss'] ?? null) !== $issuer || ! is_string($subject) || $subject === '' || strlen($subject) > 255) {
                throw new RuntimeException('Identity verification failed.');
            }

            // Explicit dispatch queues now; a queue failure must not establish a session.
            app(\Illuminate\Contracts\Bus\Dispatcher::class)->dispatch(new RevokeAetherExampleToken($identity->token));
            $request->session()->regenerate();
            $request->session()->put('aether_example', [
                'issuer' => $issuer,
                'subject' => $subject,
                'expires_at' => time() + 900,
            ]);
        } catch (Throwable) {
            $request->session()->forget('aether_example');

            return redirect('/aether-example')->withErrors(['login' => 'Sign-in was not completed. Please try again.']);
        } finally {
            $request->session()->forget(['state', 'code_verifier', 'openidconnect_nonce', 'aether_attempt_expires']);
        }

        return redirect('/aether-example');
    }

    public function logout(Request $request): RedirectResponse
    {
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect('/aether-example');
    }
}
PHP;
        $routesExample = <<<'PHP'
<?php

use App\Http\Controllers\AetherExampleController;
use Illuminate\Support\Facades\Route;

// Add to routes/web.php so session and CSRF middleware remain enabled.
// Session blocking requires a lock-capable cache such as database or Redis.
Route::get('/aether-example', [AetherExampleController::class, 'show'])->block();
Route::get('/auth/aether', [AetherExampleController::class, 'redirect'])->middleware('throttle:10,1')->block();
Route::get('/auth/aether/callback', [AetherExampleController::class, 'callback'])->middleware('throttle:10,1')->block();
Route::post('/auth/aether/logout', [AetherExampleController::class, 'logout'])->block();
PHP;
        $viewExample = <<<'BLADE'
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Aether sign-in example</title></head>
<body>
<main>
    <h1>Aether sign-in example</h1>
    @if ($errors->has('login'))
        <p role="alert">{{ $errors->first('login') }}</p>
    @endif
    @if ($identity)
        <p>Signed in as {{ $identity['subject'] }} at {{ $identity['issuer'] }}.</p>
        <form method="POST" action="/auth/aether/logout">
            @csrf
            <button type="submit">Sign out of this app</button>
        </form>
    @else
        <a href="/auth/aether">Sign in with Aether</a>
    @endif
</main>
</body>
</html>
BLADE;
    @endphp
    <pre class="developer-urls"><code>{{ $controllerExample }}</code></pre>
    <p>Add these routes to <code>routes/web.php</code>, preserving existing routes.</p>
    <pre class="developer-urls"><code>{{ $routesExample }}</code></pre>
    <p>Create <code>resources/views/aether-example.blade.php</code>.</p>
    <pre class="developer-urls"><code>{{ $viewExample }}</code></pre>
    <h3>5. Run and check the flow</h3>
    <p>After configuring the client, clear its cached configuration and start its queue worker in a separate terminal.</p>
    <pre class="developer-urls"><code>php artisan config:clear
php artisan queue:work --tries=5 --timeout=30</code></pre>
    <p>Open <code>https://your-app.example/aether-example</code>. Try sign-in, deny permission and retry, allow permission, then sign out. Reloading a callback must not reuse its code. The example asks for sign-in again after fifteen minutes.</p>
    <p>Signing out ends this app's session. Aether stays signed in, so the next sign-in may not ask for a password. Token cleanup runs separately; suspending the app does not automatically end a local session it already created.</p>
    <p>Before using this in a full app, add a unique issuer/subject user mapping, Laravel's normal auth guard and resource policies. The example's session key alone must not grant access to existing routes. If you need ongoing API access, add encrypted token storage, coordinated refreshes and queued revocation on logout.</p>
    <p>Package reference: <a href="https://socialiteproviders.com/OpenIDConnect/">Socialite OpenID Connect</a>. Queue reference: <a href="https://laravel.com/docs/13.x/queues#encrypted-jobs">Laravel encrypted jobs</a>.</p>
</details>
