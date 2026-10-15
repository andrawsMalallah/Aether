<?php

use App\Actions\Developer\PublishApplication;
use App\Enums\OAuthAppType;
use App\Enums\OAuthAuditEvent;
use App\Enums\OAuthClientStatus;
use App\Models\AuditLog;
use App\Models\OAuthClient;
use App\Models\User;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

/** @return array<string, mixed> */
function browserRegistrationData(array $overrides = []): array
{
    return array_replace([
        'app_type' => 'spa', 'name' => 'Browser application', 'homepage_url' => 'https://browser.example',
        'redirect_urls' => 'https://browser.example/callback', 'scopes' => ['openid', 'email'],
    ], $overrides);
}

it('registers an owned testing public client without secrets or privileged capabilities', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $this->actingAs($owner)->get(route('developer.apps.create'))->assertOk()->assertSee('Browser application (SPA)');
    $this->post(route('developer.apps.store'), browserRegistrationData([
        'secret' => 'injected', 'confidential' => true, 'owner_id' => 999, 'status' => 'live', 'first_party' => true,
        'grant_types' => ['client_credentials'], 'introspection_client_ids' => ['injected'],
    ]))->assertRedirect();
    $client = OAuthClient::sole();
    expect($client->secret)->toBeNull()->and($client->plainSecret)->toBeNull()->and($client->confidential())->toBeFalse()
        ->and($client->app_type)->toBe(OAuthAppType::Spa)->and($client->status)->toBe(OAuthClientStatus::Testing)
        ->and($client->owner_id)->toBe($owner->id)->and($client->owner_type)->toBe($owner->getMorphClass())
        ->and($client->first_party)->toBeFalse()->and($client->introspection_client_ids)->toBeNull()
        ->and($client->grant_types)->toBe(['authorization_code', 'refresh_token'])->and($client->allowed_scopes)->toBe(['openid', 'email']);
    expect(session('developer.credentials.'.$client->id))->toBeNull();
    $this->withSession(['developer.credentials.'.$client->id => 'invalid-stale-handoff'])
        ->get(route('developer.apps.show', $client))->assertOk()->assertHeader('Cache-Control', 'no-store, private')
        ->assertSee('No client secret is issued')->assertSee('This public client has no secret')
        ->assertSee('code_challenge_method=S256')->assertSee('Origin configuration is managed separately.')
        ->assertSee('Keep access, ID and refresh tokens in memory')->assertDontSee('Regenerate secret')
        ->assertDontSee('Save your client secret now.')->assertDontSee('invalid-stale-handoff')->assertDontSee('Store retained tokens encrypted on your server.');
    $this->withSession(['auth.password_confirmed_at' => now()->timestamp])
        ->get(route('developer.apps.secret.confirm', $client))->assertForbidden();
    $this->post(route('developer.apps.secret.store', $client), ['confirm' => true])->assertForbidden();
    expect($client->fresh()->secret)->toBeNull()->and(AuditLog::where('event', OAuthAuditEvent::ClientSecretRegenerated)->count())->toBe(0);
});

it('rejects missing malformed or unsupported registration types', function (mixed $type): void {
    $this->actingAs(User::factory()->create(['is_developer' => true]))
        ->post(route('developer.apps.store'), browserRegistrationData(['app_type' => $type]))->assertSessionHasErrors('app_type');
    expect(OAuthClient::count())->toBe(0);
})->with([null, '', 'invalid', [['spa']]]);

it('preserves exact callback and identity permission validation for browser registrations', function (array $overrides, string $error): void {
    $this->actingAs(User::factory()->create(['is_developer' => true]))
        ->post(route('developer.apps.store'), browserRegistrationData($overrides))->assertSessionHasErrors($error);
    expect(OAuthClient::count())->toBe(0);
})->with([
    [['redirect_urls' => 'https://browser.example/*'], 'redirect_uris.0'],
    [['redirect_urls' => 'http://browser.example/callback'], 'redirect_uris.0'],
    [['redirect_urls' => 'https://browser.example/#callback'], 'redirect_uris.0'],
    [['scopes' => ['openid', 'stats:read']], 'scopes.1'],
]);

it('completes secretless PKCE and rotating refresh for a portal registered client', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $this->actingAs($owner)->post(route('developer.apps.store'), browserRegistrationData())->assertRedirect();
    $client = OAuthClient::sole();
    $this->actingAs(User::factory()->create())->get(oauthAuthorizeUrl(oauthParameters($client)))->assertForbidden();
    $this->actingAs($owner)->get(oauthAuthorizeUrl([...oauthParameters($client), 'redirect_uri' => 'https://browser.example/callback/extra']))->assertStatus(401);
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
    $tokens = $this->withHeader('Origin', 'https://browser.example')->postJson('/oauth/token', $exchange)
        ->assertOk()->assertJsonStructure(['access_token', 'refresh_token', 'id_token'])->assertHeaderMissing('Access-Control-Allow-Origin')->json();
    $this->flushHeaders();
    $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$tokens['access_token']])->assertOk()->assertJsonPath('sub', (string) $owner->id);
    $refresh = ['grant_type' => 'refresh_token', 'client_id' => $client->id, 'refresh_token' => $tokens['refresh_token']];
    $replacement = $this->postJson('/oauth/token', $refresh)->assertOk()->json();
    expect($replacement['refresh_token'])->not->toBe($tokens['refresh_token']);
    $this->postJson('/oauth/token', $refresh)->assertStatus(400);
    // Reusing a refresh revokes its lineage; obtain a fresh pair for logout verification.
    $fresh = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, $owner, $client)))->assertOk()->json();
    $this->post('/oauth/revoke', ['client_id' => $client->id, 'token' => $fresh['refresh_token']])->assertOk();
    expect(oauthBearerWorks($fresh['access_token']))->toBeFalse();
    $this->postJson('/oauth/token', ['grant_type' => 'client_credentials', 'client_id' => $client->id, 'scope' => 'openid'])->assertStatus(400);
});

it('edits callbacks and scopes without converting public credentials or granting privileges', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner);
    $code = oauthCode($this, $owner, $client);
    $this->get(route('developer.apps.edit', $client))->assertOk()->assertSee('The application type cannot be changed.');
    $this->put(route('developer.apps.update', $client), browserRegistrationData([
        'app_type' => 'web', 'secret' => 'injected', 'first_party' => true, 'status' => 'testing',
        'introspection_client_ids' => ['injected'],
    ]))->assertRedirect(route('developer.apps.show', $client));
    expect($client->fresh()->app_type)->toBe(OAuthAppType::Spa)->and($client->fresh()->secret)->toBeNull()
        ->and($client->fresh()->first_party)->toBeFalse()->and($client->fresh()->status)->toBe(OAuthClientStatus::Live)
        ->and($client->fresh()->introspection_client_ids)->toBeNull()->and($client->fresh()->allowed_scopes)->toBe(['openid', 'email']);
    $this->postJson('/oauth/token', oauthExchange($client, $code))->assertStatus(400);
});

it('requires confirmed publication and allows other users only after going live', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $other = User::factory()->create();
    $this->actingAs($owner)->post(route('developer.apps.store'), browserRegistrationData())->assertRedirect();
    $client = OAuthClient::sole();
    $this->get(route('developer.apps.publish.confirm', $client))->assertRedirect(route('password.confirm'));
    $this->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    $this->post(route('developer.apps.publish.store', $client))->assertSessionHasErrors('confirm');
    $this->get(route('developer.apps.publish.confirm', $client))->assertOk();
    $this->post(route('developer.apps.publish.store', $client), ['confirm' => true])->assertRedirect();
    expect($client->fresh()->secret)->toBeNull()->and($client->fresh()->status)->toBe(OAuthClientStatus::Live);
    $this->actingAs($other)->get(oauthAuthorizeUrl(oauthParameters($client)))->assertOk()->assertSee('Allow');
});

it('blocks foreign and suspended browser management and rechecks locked publication state', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner);
    $this->actingAs(User::factory()->create(['is_developer' => true]))->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    $this->get(route('developer.apps.edit', $client))->assertForbidden();
    $this->post(route('developer.apps.publish.store', $client), ['confirm' => true])->assertForbidden();
    $this->post(route('developer.apps.delete.store', $client), ['confirm' => true])->assertForbidden();
    $this->actingAs($owner);
    $client->newQuery()->whereKey($client->id)->update(['status' => OAuthClientStatus::Suspended]);
    $this->get(route('developer.apps.edit', $client))->assertForbidden();
    expect(fn () => app(PublishApplication::class)->handle($client))->toThrow(AuthorizationException::class);
    $this->get(route('developer.apps.show', $client))->assertOk()->assertSee('This application is unavailable.');
});

it('deletes public browser applications in each supported lifecycle state', function (OAuthClientStatus $status): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner);
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, $owner, $client)))->assertOk()->json();
    $client->forceFill(['status' => $status])->save();
    $this->withSession(['auth.password_confirmed_at' => now()->timestamp])->post(route('developer.apps.delete.store', $client), ['confirm' => true])->assertRedirect();
    expect($client->fresh()->revoked)->toBeTrue()->and($client->fresh()->secret)->toBeNull()
        ->and(oauthBearerWorks($tokens['access_token']))->toBeFalse();
    $this->get(route('developer.apps.show', $client))->assertForbidden();
    $this->postJson('/oauth/token', ['grant_type' => 'refresh_token', 'client_id' => $client->id, 'refresh_token' => $tokens['refresh_token']])->assertStatus(401);
})->with(OAuthClientStatus::cases());
