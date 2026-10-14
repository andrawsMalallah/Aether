<?php

use App\Enums\OAuthAppType;
use App\Enums\OAuthClientStatus;
use App\Models\AuditLog;
use App\Models\Consent;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use phpseclib4\Crypt\RSA;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    // Generate an ephemeral test pair once; never read the local provider's signing keys.
    static $keys;
    $keys ??= RSA::createKey(2048);
    config(['passport.private_key' => (string) $keys, 'passport.public_key' => (string) $keys->getPublicKey()]);
});

it('completes public PKCE consent code token and rotating refresh with correct lifetimes', function (): void {
    $user = User::factory()->create();
    $client = oauthClientFixture();
    $parameters = oauthParameters($client, 'openid email');
    $this->actingAs($user)->get(oauthAuthorizeUrl($parameters))->assertOk()->assertSee('See your email address')->assertSee('Allow')->assertHeader('X-Frame-Options', 'DENY')->assertHeader('Cache-Control', 'no-store, private');
    $response = $this->post('/oauth/authorize', ['auth_token' => session('authToken')]);
    expect($response->getStatusCode())->toBe(302);
    parse_str(parse_url($response->headers->get('Location'), PHP_URL_QUERY), $callback);
    expect(hash_equals($parameters['state'], $callback['state']))->toBeTrue();
    $code = Passport::authCode()->newQuery()->first();
    expect(abs($code->expires_at->timestamp - now()->addMinute()->timestamp))->toBeLessThanOrEqual(2);
    $response = $this->postJson('/oauth/token', oauthExchange($client, $callback['code']));
    expect($response->getStatusCode())->toBe(200);
    expect($response->json('token_type'))->toBe('Bearer');
    expect($response->json('expires_in'))->toBe(3600);
    expect(oauthBearerWorks($response->json('access_token')))->toBeTrue();
    $oldRefresh = $response->json('refresh_token');
    $oldAccess = $response->json('access_token');
    $storedRefresh = Passport::refreshToken()->newQuery()->first();
    expect(abs($storedRefresh->expires_at->timestamp - now()->addDays(30)->timestamp))->toBeLessThanOrEqual(2);
    $response = $this->postJson('/oauth/token', ['grant_type' => 'refresh_token', 'client_id' => $client->getKey(), 'refresh_token' => $oldRefresh]);
    expect($response->getStatusCode())->toBe(200);
    expect(hash_equals($oldRefresh, $response->json('refresh_token')))->toBeFalse();
    expect(oauthBearerWorks($oldAccess))->toBeFalse();
    expect(oauthBearerWorks($response->json('access_token')))->toBeTrue();
    $this->postJson('/oauth/token', ['grant_type' => 'refresh_token', 'client_id' => $client->getKey(), 'refresh_token' => $oldRefresh])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
    expect(AuditLog::query()->where('event', 'refresh.replayed')->exists())->toBeTrue();
    expect(Consent::query()->first()->scopes)->toBe(['openid', 'email']);
});

it('rejects exact redirect mismatches without redirecting even for guests', function (string $redirect): void {
    $client = oauthClientFixture();
    $this->get(oauthAuthorizeUrl([...oauthParameters($client), 'redirect_uri' => $redirect]))->assertStatus(401)->assertHeaderMissing('Location')->assertHeader('Content-Type', 'text/html; charset=utf-8')->assertSee('Cannot continue');
})->with(['https://evil.example/callback', 'https://client.example/callback/extra', 'https://client.example/callback?extra=1', 'https://CLIENT.example/callback']);

it('requires the registered loopback port exactly', function (): void {
    $client = oauthClientFixture();
    $client->update(['redirect_uris' => ['http://localhost:8765/callback']]);
    $this->get(oauthAuthorizeUrl([...oauthParameters($client), 'redirect_uri' => 'http://localhost:8766/callback']))->assertStatus(401)->assertHeaderMissing('Location');
});

it('validates requests before guest login and preserves valid requests through login', function (): void {
    $client = oauthClientFixture();
    $this->get(oauthAuthorizeUrl([...oauthParameters($client), 'client_id' => Str::uuid()->toString()]))->assertStatus(401)->assertHeaderMissing('Location');
    $parameters = oauthParameters($client);
    $this->get(oauthAuthorizeUrl($parameters))->assertRedirect('/login');
    $this->assertGuest();
    $user = User::factory()->create();
    $response = $this->post('/login', ['email' => $user->email, 'password' => 'password']);
    expect(str_contains($response->headers->get('Location'), '/oauth/authorize?'))->toBeTrue();
    $this->get(oauthAuthorizeUrl($parameters))->assertOk()->assertSee('Allow');
});

it('requires S256 PKCE for every interactive client', function (bool $confidential): void {
    $client = oauthClientFixture(confidential: $confidential);
    $parameters = oauthParameters($client);
    unset($parameters['code_challenge']);
    $this->get(oauthAuthorizeUrl($parameters))->assertStatus(400)->assertHeaderMissing('Location');
    $this->get(oauthAuthorizeUrl([...oauthParameters($client), 'code_challenge_method' => 'plain']))->assertStatus(400)->assertHeaderMissing('Location');
    $this->get(oauthAuthorizeUrl([...oauthParameters($client), 'code_challenge_method' => []]))->assertStatus(400);
})->with([false, true]);

it('rejects wrong missing verifiers and wrong redirect at exchange without consuming a valid code', function (): void {
    $user = User::factory()->create();
    $client = oauthClientFixture();
    $code = oauthCode($this, $user, $client);
    $data = oauthExchange($client, $code);
    $this->postJson('/oauth/token', [...$data, 'code_verifier' => Str::random(64)])->assertStatus(400);
    $missingVerifier = $data;
    unset($missingVerifier['code_verifier']);
    $this->postJson('/oauth/token', $missingVerifier)->assertStatus(400);
    $this->postJson('/oauth/token', [...$data, 'redirect_uri' => 'https://evil.example/callback'])->assertStatus(400);
    expect(Passport::token()->newQuery()->count())->toBe(0);
    expect($this->postJson('/oauth/token', $data)->getStatusCode())->toBe(200);
});

it('rejects code replay and revokes the code token lineage including refreshed tokens', function (): void {
    $user = User::factory()->create();
    $client = oauthClientFixture();
    $data = oauthExchange($client, oauthCode($this, $user, $client));
    $tokens = $this->postJson('/oauth/token', $data)->json();
    $fresh = $this->postJson('/oauth/token', ['grant_type' => 'refresh_token', 'client_id' => $client->getKey(), 'refresh_token' => $tokens['refresh_token']]);
    expect($fresh->getStatusCode())->toBe(200);
    $this->postJson('/oauth/token', $data)->assertStatus(400);
    expect(oauthBearerWorks($fresh->json('access_token')))->toBeFalse();
    expect(Passport::refreshToken()->newQuery()->where('revoked', false)->exists())->toBeFalse();
    expect(AuditLog::query()->where('event', 'code.replayed')->exists())->toBeTrue();
});

it('rejects expired codes and cross-client redemption', function (): void {
    $user = User::factory()->create();
    $client = oauthClientFixture();
    $code = oauthCode($this, $user, $client);
    $other = oauthClientFixture();
    $this->postJson('/oauth/token', oauthExchange($other, $code))->assertStatus(400);
    $this->travel(61)->seconds();
    $this->postJson('/oauth/token', oauthExchange($client, $code))->assertStatus(400);
    expect(Passport::token()->newQuery()->count())->toBe(0);
});

it('persists consent beyond token expiry and prompts only for expanded or revoked scopes', function (): void {
    $user = User::factory()->create();
    $client = oauthClientFixture();
    oauthCode($this, $user, $client, 'openid');
    $this->get(oauthAuthorizeUrl(oauthParameters($client, 'openid')))->assertStatus(302);
    $this->get(oauthAuthorizeUrl(oauthParameters($client, 'openid email')))->assertOk()->assertSee('See your email address');
    $this->post('/oauth/authorize', ['auth_token' => session('authToken')]);
    expect(Consent::query()->first()->scopes)->toBe(['openid', 'email']);
    $this->get(oauthAuthorizeUrl([...oauthParameters($client), 'prompt' => 'consent']))->assertOk();
    Consent::query()->update(['revoked_at' => now()]);
    $this->get(oauthAuthorizeUrl(oauthParameters($client)))->assertOk();
});

it('skips first-party consent only via the vetted flag and respects forced consent', function (): void {
    $user = User::factory()->create();
    $client = oauthClientFixture();
    expect($client->owner_id)->toBeNull();
    $this->actingAs($user)->get(oauthAuthorizeUrl(oauthParameters($client)))->assertOk();
    $client->forceFill(['first_party' => true])->save();
    $this->get(oauthAuthorizeUrl(oauthParameters($client)))->assertStatus(302);
    $this->get(oauthAuthorizeUrl([...oauthParameters($client), 'prompt' => 'consent']))->assertOk();
});

it('denies consent without saving a grant and consumes the consent form once', function (): void {
    $user = User::factory()->create();
    $client = oauthClientFixture();
    $this->actingAs($user)->get(oauthAuthorizeUrl(oauthParameters($client)))->assertOk();
    $authToken = session('authToken');
    $response = $this->delete('/oauth/authorize', ['auth_token' => $authToken]);
    expect($response->getStatusCode())->toBe(302);
    parse_str(parse_url($response->headers->get('Location'), PHP_URL_QUERY), $parameters);
    expect($parameters['error'])->toBe('access_denied');
    expect(Consent::query()->count())->toBe(0);
    $this->post('/oauth/authorize', ['auth_token' => $authToken])->assertStatus(403);
});

it('checks the signed-in user and current restrictions again on consent submission', function (): void {
    $user = User::factory()->create();
    $client = oauthClientFixture();
    $this->actingAs($user)->get(oauthAuthorizeUrl(oauthParameters($client)))->assertOk();
    $this->actingAs(User::factory()->create())->post('/oauth/authorize', ['auth_token' => session('authToken')])->assertStatus(401)->assertHeaderMissing('Location');
    expect(Consent::query()->count())->toBe(0);
    $this->actingAs($user)->get(oauthAuthorizeUrl(oauthParameters($client)))->assertOk();
    $client->forceFill(['status' => OAuthClientStatus::Suspended])->save();
    $this->post('/oauth/authorize', ['auth_token' => session('authToken')])->assertStatus(403)->assertHeaderMissing('Location');
    expect(Passport::authCode()->newQuery()->count())->toBe(0);
});

it('blocks scope escalation at authorization machine issuance and refresh', function (): void {
    $user = User::factory()->create();
    $client = oauthClientFixture();
    $client->forceFill(['allowed_scopes' => ['openid']])->save();
    $this->actingAs($user)->get(oauthAuthorizeUrl(oauthParameters($client, 'openid email')))->assertStatus(400)->assertHeaderMissing('Location');
    $this->get(oauthAuthorizeUrl(oauthParameters($client, '*')))->assertStatus(400);
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, $user, $client)))->json();
    $this->postJson('/oauth/token', ['grant_type' => 'refresh_token', 'client_id' => $client->getKey(), 'refresh_token' => $tokens['refresh_token'], 'scope' => 'openid email'])->assertStatus(400);
});

it('restricts testing to its verified owner and rejects suspended clients and their live tokens', function (): void {
    $owner = User::factory()->create();
    $client = oauthClientFixture($owner);
    $client->forceFill(['status' => OAuthClientStatus::Testing])->save();
    $this->actingAs(User::factory()->create())->get(oauthAuthorizeUrl(oauthParameters($client)))->assertStatus(403)->assertHeaderMissing('Location');
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, $owner, $client)))->json();
    expect(oauthBearerWorks($tokens['access_token']))->toBeTrue();
    $client->forceFill(['status' => OAuthClientStatus::Suspended])->save();
    expect(oauthBearerWorks($tokens['access_token']))->toBeFalse();
    $this->get(oauthAuthorizeUrl(oauthParameters($client)))->assertStatus(401)->assertHeaderMissing('Location');
    $this->postJson('/oauth/token', ['grant_type' => 'refresh_token', 'client_id' => $client->getKey(), 'refresh_token' => $tokens['refresh_token']])->assertStatus(401);
});

it('requires verified users and rechecks testing restrictions on token issuance', function (): void {
    $user = User::factory()->unverified()->create();
    $client = oauthClientFixture();
    $this->actingAs($user)->get(oauthAuthorizeUrl(oauthParameters($client)))->assertStatus(403);
    $user->markEmailAsVerified();
    $code = oauthCode($this, $user, $client);
    $client->forceFill(['status' => OAuthClientStatus::Testing])->save();
    $this->postJson('/oauth/token', oauthExchange($client, $code))->assertStatus(401);
});

it('stores confidential secrets hashed and rejects the previous secret after regeneration', function (): void {
    $user = User::factory()->create();
    $client = oauthClientFixture(confidential: true);
    expect(Hash::check($client->plainSecret, $client->secret))->toBeTrue();
    expect($client->fresh()->plainSecret)->toBeNull();
    expect($client->toArray())->not->toHaveKey('secret');
    $code = oauthCode($this, $user, $client);
    $data = oauthExchange($client, $code);
    app(ClientRepository::class)->regenerateSecret($client);
    $this->postJson('/oauth/token', $data)->assertStatus(401);
    expect($this->postJson('/oauth/token', [...$data, 'client_secret' => $client->plainSecret])->getStatusCode())->toBe(200);
});

it('issues scope-limited machine tokens only for confidential live machine clients', function (): void {
    $client = app(ClientRepository::class)->createClientCredentialsGrantClient('Machine test');
    $client->forceFill(['status' => OAuthClientStatus::Live, 'app_type' => OAuthAppType::Machine, 'allowed_scopes' => ['profile']])->save();
    $credentials = ['grant_type' => 'client_credentials', 'client_id' => $client->getKey(), 'client_secret' => $client->plainSecret];
    $response = $this->postJson('/oauth/token', [...$credentials, 'scope' => 'profile']);
    expect($response->getStatusCode())->toBe(200);
    expect($response->json('refresh_token'))->toBeNull();
    expect(Passport::token()->newQuery()->first()->scopes)->toBe(['profile']);
    expect(oauthBearerWorks($response->json('access_token')))->toBeTrue();
    $this->postJson('/oauth/token', [...$credentials, 'scope' => 'email'])->assertStatus(400);
    $public = oauthClientFixture();
    $this->postJson('/oauth/token', ['grant_type' => 'client_credentials', 'client_id' => $public->getKey()])->assertStatus(400);
    $client->forceFill(['status' => OAuthClientStatus::Testing])->save();
    $this->postJson('/oauth/token', $credentials)->assertStatus(400);
});

it('supports Basic client authentication without allowing mixed authentication methods', function (): void {
    $client = oauthClientFixture(confidential: true);
    $data = oauthExchange($client, oauthCode($this, User::factory()->create(), $client));
    unset($data['client_id'], $data['client_secret']);
    $headers = ['Authorization' => 'Basic '.base64_encode($client->getKey().':'.$client->plainSecret)];
    expect($this->postJson('/oauth/token', $data, $headers)->getStatusCode())->toBe(200);
    $this->postJson('/oauth/token', [...$data, 'client_id' => $client->getKey()], $headers)->assertStatus(400);
});

it('revokes access and associated refresh tokens and treats unknown tokens identically', function (string $hint): void {
    $client = oauthClientFixture();
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, User::factory()->create(), $client)))->json();
    $this->postJson('/oauth/revoke', ['client_id' => $client->getKey(), 'token' => $tokens[$hint], 'token_type_hint' => 'incorrect_hint'])->assertOk()->assertContent('')->assertHeader('Cache-Control', 'no-store, private');
    expect(oauthBearerWorks($tokens['access_token']))->toBeFalse();
    $this->postJson('/oauth/token', ['grant_type' => 'refresh_token', 'client_id' => $client->getKey(), 'refresh_token' => $tokens['refresh_token']])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
    $this->postJson('/oauth/revoke', ['client_id' => $client->getKey(), 'token' => Str::random(64)])->assertOk()->assertContent('');
})->with(['access_token', 'refresh_token']);

it('prevents cross-client revocation and requires valid confidential credentials', function (): void {
    $client = oauthClientFixture(confidential: true);
    $other = oauthClientFixture();
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, User::factory()->create(), $client)))->json();
    foreach (['access_token', 'refresh_token'] as $type) {
        $this->postJson('/oauth/revoke', ['client_id' => $other->getKey(), 'token' => $tokens[$type]])->assertOk();
    }
    expect(oauthBearerWorks($tokens['access_token']))->toBeTrue();
    $this->postJson('/oauth/revoke', ['client_id' => $client->getKey(), 'client_secret' => Str::random(40), 'token' => $tokens['access_token']])->assertStatus(401);
    expect(oauthBearerWorks($tokens['access_token']))->toBeTrue();
});

it('does not expose unsupported grants or Passport client management endpoints', function (): void {
    $client = oauthClientFixture();
    foreach (['password', 'implicit', 'personal_access', 'urn:ietf:params:oauth:grant-type:device_code'] as $grant) {
        $this->postJson('/oauth/token', ['grant_type' => $grant, 'client_id' => $client->getKey()])->assertStatus(400);
    }
    $this->get(oauthAuthorizeUrl([...oauthParameters($client), 'response_type' => 'token']))->assertStatus(400)->assertHeaderMissing('Location');
    foreach (['/oauth/clients', '/oauth/tokens', '/oauth/scopes', '/oauth/device', '/oauth/personal-access-tokens', '/oauth/introspect'] as $path) {
        $this->getJson($path)->assertNotFound();
    }
});

it('rejects malformed protocol inputs without flashing credentials or returning exception details', function (): void {
    $this->post('/oauth/token', ['grant_type' => [], 'client_secret' => ['invalid'], 'code' => ['invalid']])->assertStatus(400)->assertJsonPath('error', 'invalid_request')->assertSessionMissing('_old_input');
    $this->postJson('/oauth/revoke', ['token' => []])->assertStatus(400);
    $this->get('/oauth/authorize?client_id[]=invalid')->assertStatus(400)->assertHeaderMissing('Location');
});

it('rate limits authorization token and revocation with separate limits', function (): void {
    $client = oauthClientFixture();
    session()->start();
    $this->withCookie(config('session.cookie'), session()->getId());
    for ($attempt = 0; $attempt < 30; $attempt++) {
        $this->get('/oauth/authorize')->assertStatus(400);
    }
    $this->get('/oauth/authorize')->assertStatus(429);
    for ($attempt = 0; $attempt < 60; $attempt++) {
        $this->postJson('/oauth/token', ['client_id' => $client->getKey()])->assertStatus(400);
    }
    $this->postJson('/oauth/token', ['client_id' => $client->getKey()])->assertStatus(429);
    for ($attempt = 0; $attempt < 60; $attempt++) {
        $this->postJson('/oauth/revoke', ['client_id' => $client->getKey(), 'token' => Str::random(64)])->assertOk();
    }
    $this->postJson('/oauth/revoke', ['client_id' => $client->getKey(), 'token' => Str::random(64)])->assertStatus(429);
});

it('rechecks redirect scopes and app type after the consent screen was opened', function (string $change): void {
    $client = oauthClientFixture();
    $this->actingAs(User::factory()->create())->get(oauthAuthorizeUrl(oauthParameters($client, 'openid email')))->assertOk();
    $client->forceFill(match ($change) {
        'redirect' => ['redirect_uris' => ['https://different.example/callback']],
        'scopes' => ['allowed_scopes' => ['openid']],
        'type' => ['app_type' => OAuthAppType::Machine],
    })->save();
    $this->post('/oauth/authorize', ['auth_token' => session('authToken')])->assertStatus(400)->assertHeaderMissing('Location');
    expect(Consent::query()->exists())->toBeFalse();
    expect(Passport::authCode()->newQuery()->exists())->toBeFalse();
})->with(['redirect', 'scopes', 'type']);

it('blocks removed scopes for existing tokens and refresh requests', function (): void {
    $client = oauthClientFixture();
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, User::factory()->create(), $client, 'openid email')))->json();
    $client->forceFill(['allowed_scopes' => ['openid']])->save();
    expect(oauthBearerWorks($tokens['access_token']))->toBeFalse();
    $this->postJson('/oauth/token', ['grant_type' => 'refresh_token', 'client_id' => $client->getKey(), 'refresh_token' => $tokens['refresh_token']])->assertStatus(400);
});

it('does not revoke another client token lineage on a cross-client code replay', function (): void {
    $client = oauthClientFixture();
    $code = oauthCode($this, User::factory()->create(), $client);
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, $code))->json();
    $this->postJson('/oauth/token', oauthExchange(oauthClientFixture(), $code))->assertStatus(400);
    expect(oauthBearerWorks($tokens['access_token']))->toBeTrue();
    expect(AuditLog::query()->where('event', 'code.replayed')->exists())->toBeFalse();
});

it('rejects expired refresh tokens and wildcard scopes even if incorrectly registered', function (): void {
    $client = oauthClientFixture();
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, User::factory()->create(), $client)))->json();
    Passport::refreshToken()->newQuery()->update(['expires_at' => now()->subSecond()]);
    $this->postJson('/oauth/token', ['grant_type' => 'refresh_token', 'client_id' => $client->getKey(), 'refresh_token' => $tokens['refresh_token']])->assertStatus(400);
    $client->forceFill(['allowed_scopes' => ['*']])->save();
    $this->get(oauthAuthorizeUrl(oauthParameters($client, '*')))->assertStatus(400)->assertHeaderMissing('Location');
});

it('serves a consent logo only to an eligible user and rejects active content', function (): void {
    Storage::fake('local');
    $owner = User::factory()->create();
    $client = oauthClientFixture($owner);
    $path = UploadedFile::fake()->image('logo.png')->store('oauth-client-logos', 'local');
    $client->forceFill(['status' => OAuthClientStatus::Testing, 'logo_path' => $path])->save();
    $this->actingAs($owner)->get(oauthAuthorizeUrl(oauthParameters($client)))->assertOk()->assertSee('Test application logo');
    $this->get('/oauth/clients/'.$client->getKey().'/logo')->assertOk()->assertHeader('X-Content-Type-Options', 'nosniff');
    $this->actingAs(User::factory()->create())->get('/oauth/clients/'.$client->getKey().'/logo')->assertStatus(403);
    Storage::disk('local')->put('oauth-client-logos/invalid.svg', '<svg xmlns="http://www.w3.org/2000/svg"></svg>');
    $client->update(['logo_path' => 'oauth-client-logos/invalid.svg']);
    $this->actingAs($owner)->get('/oauth/clients/'.$client->getKey().'/logo')->assertNotFound();
});
