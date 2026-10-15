<?php

use App\Actions\Developer\DeleteApplication;
use App\Actions\Developer\PublishApplication;
use App\Actions\Developer\UpdateApplication;
use App\Enums\OAuthAppType;
use App\Enums\OAuthClientStatus;
use App\Models\OAuthClient;
use App\Models\User;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

/** @return array<string, mixed> */
function mobileRegistrationData(array $overrides = []): array
{
    return array_replace([
        'app_type' => 'mobile', 'name' => 'Native notes', 'homepage_url' => 'https://native.example',
        'redirect_urls' => 'https://native.example/auth/callback', 'scopes' => ['openid', 'email'],
    ], $overrides);
}

it('registers an owned testing secretless mobile client with native guidance and fixed grants', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $this->actingAs($owner)->get(route('developer.apps.create'))->assertOk()->assertSee('Mobile application (native)');
    $this->post(route('developer.apps.store'), mobileRegistrationData([
        'secret' => 'injected', 'owner_id' => 999, 'owner_type' => 'Other', 'status' => 'live', 'first_party' => true,
        'grant_types' => ['client_credentials'], 'allowed_scopes' => ['stats:read'], 'introspection_client_ids' => [],
    ]))->assertRedirect();
    $client = OAuthClient::sole();
    expect($client->app_type)->toBe(OAuthAppType::Mobile)->and($client->status)->toBe(OAuthClientStatus::Testing)
        ->and($client->secret)->toBeNull()->and($client->plainSecret)->toBeNull()->and($client->confidential())->toBeFalse()
        ->and($client->owner_id)->toBe($owner->id)->and($client->owner_type)->toBe($owner->getMorphClass())
        ->and($client->grant_types)->toBe(['authorization_code', 'refresh_token'])->and($client->allowed_scopes)->toBe(['openid', 'email'])
        ->and($client->redirect_uris)->toBe(['https://native.example/auth/callback'])
        ->and($client->first_party)->toBeFalse()->and($client->introspection_client_ids)->toBeNull()
        ->and(session('developer.credentials.'.$client->id))->toBeNull();
    $this->withSession(['developer.credentials.'.$client->id => 'invalid-old-secret'])
        ->get(route('developer.apps.show', $client))->assertOk()->assertHeader('Cache-Control', 'no-store, private')
        ->assertSee('Connect your Mobile application')->assertSee('No client secret is issued')->assertSee('code_challenge_method=S256')
        ->assertSee('system browser')->assertSee('secure credential storage')->assertSee('does not verify or configure your platform association')
        ->assertDontSee('Regenerate secret')->assertDontSee('invalid-old-secret')->assertDontSee('Before browser integration')
        ->assertDontSee('Keep access, ID and refresh tokens in memory, not localStorage');
    expect(session('developer.credentials.'.$client->id))->toBeNull();
    $this->withSession(['auth.password_confirmed_at' => now()->timestamp])->post(route('developer.apps.secret.store', $client), ['confirm' => true])->assertForbidden();
    $this->get(route('developer.apps.secret.confirm', $client))->assertForbidden();
    $this->get(route('developer.apps.index'))->assertOk()->assertSee('Mobile application');
});

it('requires verified developer access for mobile registration', function (): void {
    $this->post(route('developer.apps.store'), mobileRegistrationData())->assertRedirect('/login');
    $this->actingAs(User::factory()->unverified()->create(['is_developer' => true]))->post(route('developer.apps.store'), mobileRegistrationData())->assertRedirect('/email/verify');
    $this->actingAs(User::factory()->create())->post(route('developer.apps.store'), mobileRegistrationData())->assertForbidden();
    expect(OAuthClient::count())->toBe(0);
});

it('requires exact https callbacks without schemes credentials fragments or wildcards', function (string $callback): void {
    $this->actingAs(User::factory()->create(['is_developer' => true]))
        ->post(route('developer.apps.store'), mobileRegistrationData(['redirect_urls' => $callback]))->assertSessionHasErrors('redirect_uris.0');
    expect(OAuthClient::count())->toBe(0);
})->with([
    'com.example.app:/auth/callback', 'myapp://callback', 'http://native.example/callback',
    'http://localhost:8765/callback', 'http://127.0.0.1:8765/callback', 'http://[::1]:8765/callback',
    'https://native.example/*', 'https://native.example/%2A', 'https://native.example/callback#fragment',
    'https://user:password@native.example/callback',
]);

it('preserves the mobile type and https-only callback rule during owner settings changes', function (): void {
    Storage::fake('local');
    $owner = User::factory()->create(['is_developer' => true]);
    $this->actingAs($owner)->post(route('developer.apps.store'), mobileRegistrationData());
    $client = OAuthClient::sole();
    $this->get(route('developer.apps.edit', $client))->assertOk()->assertSee('Custom schemes, HTTP and wildcards are not supported.');
    $this->put(route('developer.apps.update', $client), mobileRegistrationData([
        'app_type' => 'web', 'name' => 'Updated native notes', 'redirect_urls' => 'https://native.example/auth/new',
        'logo' => UploadedFile::fake()->image('logo.png'), 'scopes' => ['openid'], 'secret' => 'injected', 'status' => 'live',
    ]))->assertSessionHasNoErrors()->assertRedirect();
    expect($client->fresh()->app_type)->toBe(OAuthAppType::Mobile)->and($client->fresh()->secret)->toBeNull()
        ->and($client->fresh()->status)->toBe(OAuthClientStatus::Testing)->and($client->fresh()->allowed_scopes)->toBe(['openid'])
        ->and($client->fresh()->redirect_uris)->toBe(['https://native.example/auth/new']);
    Storage::disk('local')->assertExists($client->fresh()->logo_path);
    $this->put(route('developer.apps.update', $client), mobileRegistrationData(['app_type' => 'web', 'redirect_urls' => 'http://localhost:8765/callback']))->assertSessionHasErrors('redirect_uris.0');
    $this->put(route('developer.apps.update', $client), mobileRegistrationData(['app_type' => 'spa', 'redirect_urls' => 'myapp://callback']))->assertSessionHasErrors('redirect_uris.0');
    $this->put(route('developer.apps.update', $client), mobileRegistrationData(['scopes' => ['openid', 'stats:read']]))->assertSessionHasErrors('scopes.1');
});

it('completes mobile pkce identity refresh and revocation with exact callbacks and no secret', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $this->actingAs($owner)->post(route('developer.apps.store'), mobileRegistrationData());
    $client = OAuthClient::sole();
    $this->actingAs(User::factory()->create())->get(oauthAuthorizeUrl(oauthParameters($client)))->assertForbidden();
    $this->actingAs($owner)->get(oauthAuthorizeUrl([...oauthParameters($client), 'redirect_uri' => 'https://native.example/auth/callback/extra']))->assertStatus(401);
    $parameters = oauthParameters($client);
    unset($parameters['code_challenge']);
    $this->get(oauthAuthorizeUrl($parameters))->assertStatus(400);
    $this->get(oauthAuthorizeUrl([...oauthParameters($client), 'code_challenge_method' => 'plain']))->assertStatus(400);
    $code = oauthCode($this, $owner, $client);
    $exchange = oauthExchange($client, $code);
    $this->postJson('/oauth/token', [...$exchange, 'code_verifier' => Str::random(64)])->assertStatus(400);
    $missingVerifier = $exchange;
    unset($missingVerifier['code_verifier']);
    $this->postJson('/oauth/token', $missingVerifier)->assertStatus(400);
    $tokens = $this->postJson('/oauth/token', $exchange)->assertOk()->assertJsonStructure(['access_token', 'refresh_token', 'id_token'])->json();
    $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$tokens['access_token']])->assertOk()->assertJsonPath('sub', (string) $owner->id);
    $refresh = ['grant_type' => 'refresh_token', 'client_id' => $client->id, 'refresh_token' => $tokens['refresh_token']];
    $replacement = $this->postJson('/oauth/token', $refresh)->assertOk()->json();
    expect($replacement['refresh_token'])->not->toBe($tokens['refresh_token']);
    $this->postJson('/oauth/token', $refresh)->assertStatus(400);
    expect(oauthBearerWorks($tokens['access_token']))->toBeFalse();
    $fresh = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, $owner, $client)))->assertOk()->json();
    $this->post('/oauth/revoke', ['client_id' => $client->id, 'token' => $fresh['refresh_token']])->assertOk();
    expect(oauthBearerWorks($fresh['access_token']))->toBeFalse();
    $code = oauthCode($this, $owner, $client);
    $this->put(route('developer.apps.update', $client), mobileRegistrationData(['redirect_urls' => 'https://native.example/auth/new']))->assertRedirect();
    $this->postJson('/oauth/token', oauthExchange($client, $code))->assertStatus(400);
});

it('gates mobile publication on recent password and readiness and then permits other verified users', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $other = User::factory()->create();
    $this->actingAs($owner)->post(route('developer.apps.store'), mobileRegistrationData());
    $client = OAuthClient::sole();
    $this->post(route('developer.apps.publish.store', $client), ['confirm' => true])->assertRedirect(route('password.confirm'));
    $this->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    $this->post(route('developer.apps.publish.store', $client))->assertSessionHasErrors('confirm');
    $this->post(route('developer.apps.publish.store', $client), ['confirm' => true])->assertRedirect();
    expect($client->fresh()->status)->toBe(OAuthClientStatus::Live)->and($client->fresh()->secret)->toBeNull();
    $this->actingAs($other)->get(oauthAuthorizeUrl(oauthParameters($client)))->assertOk()->assertSee('Allow');
});

it('blocks foreign suspended and malformed mobile management and rechecks locked state', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $this->actingAs($owner)->post(route('developer.apps.store'), mobileRegistrationData());
    $client = OAuthClient::sole();
    $this->actingAs(User::factory()->create(['is_developer' => true]))->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    $this->get(route('developer.apps.edit', $client))->assertForbidden();
    $this->post(route('developer.apps.publish.store', $client), ['confirm' => true])->assertForbidden();
    $this->post(route('developer.apps.delete.store', $client), ['confirm' => true])->assertForbidden();
    $this->actingAs($owner);
    $client->newQuery()->whereKey($client->id)->update(['status' => OAuthClientStatus::Suspended]);
    expect(fn () => app(PublishApplication::class)->handle($client))->toThrow(AuthorizationException::class);
    expect(fn () => app(UpdateApplication::class)->handle($client, ['name' => 'Stale']))->toThrow(AuthorizationException::class);
    $this->get(route('developer.apps.show', $client))->assertOk()->assertSee('This application is unavailable.');
    $client->newQuery()->whereKey($client->id)->update(['secret' => 'invalid-confidential-model', 'status' => OAuthClientStatus::Testing]);
    $this->get(route('developer.apps.edit', $client))->assertForbidden();
    expect(fn () => app(DeleteApplication::class)->handle($client))->toThrow(AuthorizationException::class);
});

it('deletes public mobile clients in every lifecycle state and invalidates their credentials', function (OAuthClientStatus $status): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $this->actingAs($owner)->post(route('developer.apps.store'), mobileRegistrationData());
    $client = OAuthClient::sole();
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, $owner, $client)))->assertOk()->json();
    $client->forceFill(['status' => $status])->save();
    $this->post(route('developer.apps.delete.store', $client), ['confirm' => true])->assertRedirect(route('password.confirm'));
    $this->withSession(['auth.password_confirmed_at' => now()->timestamp])->post(route('developer.apps.delete.store', $client))->assertSessionHasErrors('confirm');
    $this->post(route('developer.apps.delete.store', $client), ['confirm' => true])->assertRedirect();
    expect($client->fresh()->revoked)->toBeTrue()->and($client->fresh()->secret)->toBeNull()->and(oauthBearerWorks($tokens['access_token']))->toBeFalse();
    $this->get(route('developer.apps.show', $client))->assertForbidden();
    $this->postJson('/oauth/token', ['grant_type' => 'refresh_token', 'client_id' => $client->id, 'refresh_token' => $tokens['refresh_token']])->assertStatus(401);
})->with(OAuthClientStatus::cases());
