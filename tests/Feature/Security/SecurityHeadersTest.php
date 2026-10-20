<?php

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Vite;
use Illuminate\Testing\TestResponse;

uses(RefreshDatabase::class);

function assertBrowserProtection(TestResponse $response): void
{
    $response->assertHeader('X-Frame-Options', 'DENY')
        ->assertHeader('X-Content-Type-Options', 'nosniff')
        ->assertHeader('Referrer-Policy', 'no-referrer')
        ->assertHeaderMissing('Strict-Transport-Security');
    $policies = $response->headers->all('Content-Security-Policy');
    expect($policies)->toHaveCount(1);
    $policy = $policies[0];
    foreach (['default-src', 'script-src', 'style-src', 'img-src', 'font-src', 'connect-src'] as $directive) {
        expect(explode('; ', $policy))->toContain($directive." 'self'");
    }
    foreach (['frame-ancestors', 'base-uri', 'object-src', 'frame-src', 'script-src-attr', 'style-src-attr'] as $directive) {
        expect(explode('; ', $policy))->toContain($directive." 'none'");
    }
    foreach (['unsafe-inline', 'unsafe-eval', 'localhost', '127.0.0.1', 'ws:', 'data:', '*', 'form-action', 'upgrade-insecure-requests'] as $source) {
        expect($policy)->not->toContain($source);
    }
}

it('protects public pages and authenticated redirects', function (string $path): void {
    assertBrowserProtection($this->get($path));
})->with(['/', '/login', '/register', '/forgot-password', '/reset-password/test', '/terms', '/privacy', '/two-factor-challenge', '/account/profile', '/admin/apps', '/developer/apps']);

it('protects verified account pages without changing private caching', function (): void {
    config(['session.driver' => 'database', 'session.connection' => null]);
    $this->actingAs(User::factory()->create())->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    foreach (['/account/profile', '/account/security', '/account/sessions', '/account/connected-apps', '/account/export', '/account/deletion'] as $path) {
        $response = $this->get($path)->assertOk();
        assertBrowserProtection($response);
    }
});

it('protects authorized developer and confirmed two-factor administrator pages', function (): void {
    $user = User::factory()->create();
    $user->forceFill([
        'is_developer' => true, 'is_admin' => true,
        'two_factor_secret' => encrypt('JBSWY3DPEHPK3PXP'),
        'two_factor_confirmed_at' => now(),
    ])->save();
    $this->actingAs($user);
    foreach (['/developer/apps', '/admin/apps', '/admin/users', '/admin/audit'] as $path) {
        $response = $this->get($path)->assertOk();
        assertBrowserProtection($response);
        $response->assertHeader('Cache-Control', str_starts_with($path, '/admin/') ? 'no-store, private' : 'no-cache, private');
    }
});

it('protects rendered exceptions and preserves status and retry headers', function (int $status): void {
    Route::get('/header-test-error', function () use ($status): void {
        if ($status === 500) {
            throw new RuntimeException('private-error-sentinel');
        }
        abort($status, '', $status === 429 ? ['Retry-After' => '37'] : []);
    });
    $response = $this->get('/header-test-error')->assertStatus($status)->assertDontSee('private-error-sentinel');
    assertBrowserProtection($response);
    $response->assertDontSee('<style', false)->assertDontSee('style=', false)
        ->assertSee('Go to Aether home');
    if ($status === 429) {
        $response->assertHeader('Retry-After', '37');
    }
})->with([403, 404, 405, 419, 429, 500, 503]);

it('protects real csrf failures validation failures and unmatched routes', function (): void {
    // Laravel normally bypasses CSRF in tests; use its real request path here.
    $this->app->instance('env', 'production');
    assertBrowserProtection($this->post('/login')->assertStatus(419));
    $this->app->instance('env', 'testing');
    assertBrowserProtection($this->postJson('/login', [])->assertUnprocessable());
    assertBrowserProtection($this->from('/login')->post('/login', [])->assertRedirect('/login'));
    assertBrowserProtection($this->get('/no-such-header-route')->assertNotFound());
});

it('preserves streamed attachments and private caching', function (): void {
    Route::get('/header-test-download', fn () => response()->streamDownload(function (): void {
        echo '{"safe":true}';
    }, 'export.json', ['Content-Type' => 'application/json', 'Cache-Control' => 'no-store, private']));
    $response = $this->get('/header-test-download')->assertOk()
        ->assertHeader('Content-Type', 'application/json')
        ->assertHeader('Cache-Control', 'no-store, private')
        ->assertDownload('export.json')->assertStreamedContent('{"safe":true}');
    assertBrowserProtection($response);
});

it('uses built assets even when the default development hot file exists', function (): void {
    expect(Vite::hotFile())->toBe('')->and(Vite::isRunningHot())->toBeFalse();
    $response = $this->get('/login')->assertOk();
    $response->assertSee('/build/assets/', false)->assertDontSee('@vite/client', false);
    assertBrowserProtection($response);
});

it('preserves protocol privacy cors and cross-origin consent redirects', function (): void {
    config(['cors.allowed_origins' => ['http://localhost:5173']]);
    $response = $this->options('/oauth/token', [], ['Origin' => 'http://localhost:5173', 'Access-Control-Request-Method' => 'POST']);
    $response->assertNoContent()->assertHeader('Access-Control-Allow-Origin', 'http://localhost:5173')->assertHeaderMissing('Access-Control-Allow-Credentials');
    assertBrowserProtection($response);
    foreach (['/.well-known/openid-configuration', '/.well-known/jwks.json', '/oauth/userinfo', '/oauth/authorize'] as $path) {
        $response = $this->getJson($path);
        assertBrowserProtection($response);
        $response->assertHeader('Cache-Control', 'no-store, private');
    }
    $user = User::factory()->create();
    $client = oauthClientFixture($user);
    $code = oauthCode($this, $user, $client);
    assertBrowserProtection($this->post('/oauth/token', oauthExchange($client, $code))->assertOk());
    $this->get(oauthAuthorizeUrl(oauthParameters($client)))->assertRedirectContains('https://client.example/callback');
});
