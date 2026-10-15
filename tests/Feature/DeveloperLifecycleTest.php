<?php

use App\Enums\OAuthAppType;
use App\Enums\OAuthAuditEvent;
use App\Enums\OAuthClientStatus;
use App\Models\AuditLog;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Hash;
use Laravel\Passport\Passport;

uses(RefreshDatabase::class);

function webApplicationSettings(array $overrides = []): array
{
    return array_replace([
        'name' => 'Updated web application', 'homepage_url' => 'https://updated.example',
        'redirect_urls' => 'https://updated.example/callback', 'scopes' => ['openid', 'email'],
    ], $overrides);
}

it('edits owned web settings while preserving lifecycle trust ownership and secret', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner, true);
    $oldHash = $client->secret;
    $this->actingAs($owner)->get(route('developer.apps.edit', $client))->assertOk()->assertSee($client->name);
    $this->put(route('developer.apps.update', $client), webApplicationSettings([
        'owner_id' => 999, 'status' => 'suspended', 'app_type' => 'm2m', 'first_party' => true,
        'grant_types' => ['client_credentials'], 'secret' => 'injected', 'introspection_client_ids' => ['injected'],
    ]))->assertRedirect(route('developer.apps.show', $client));
    $updated = $client->fresh();
    expect($updated->name)->toBe('Updated web application')->and($updated->homepage_url)->toBe('https://updated.example')
        ->and($updated->redirect_uris)->toBe(['https://updated.example/callback'])
        ->and($updated->allowed_scopes)->toBe(['openid', 'email'])->and($updated->status)->toBe(OAuthClientStatus::Live)
        ->and($updated->app_type)->toBe(OAuthAppType::Web)->and($updated->owner_id)->toBe($owner->id)
        ->and($updated->first_party)->toBeFalse()->and($updated->introspection_client_ids)->toBeNull()
        ->and($updated->secret)->toBe($oldHash)->and($updated->grant_types)->toBe(['authorization_code', 'refresh_token'])
        ->and(AuditLog::sole()->event)->toBe(OAuthAuditEvent::ClientUpdated);
});

it('returns invalid settings to the owned edit page and leaves configuration unchanged', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner, true);
    $original = $client->fresh()->getRawOriginal();
    $this->actingAs($owner)->put(route('developer.apps.update', $client), webApplicationSettings(['redirect_urls' => 'https://updated.example/*', 'scopes' => ['openid', 'stats:read']]))
        ->assertRedirect(route('developer.apps.edit', $client))->assertSessionHasErrors(['redirect_uris.0', 'scopes.1']);
    expect($client->fresh()->getRawOriginal())->toBe($original);
});

it('requires recent password confirmation and explicit confirmation for sensitive changes', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner, true);
    $client->forceFill(['status' => OAuthClientStatus::Testing])->save();
    $oldHash = $client->secret;
    $this->actingAs($owner)->get(route('developer.apps.secret.confirm', $client))->assertRedirect(route('password.confirm'));
    $this->post(route('developer.apps.secret.store', $client), ['confirm' => true])->assertRedirect(route('password.confirm'));
    $this->get(route('developer.apps.publish.confirm', $client))->assertRedirect(route('password.confirm'));
    $this->post(route('developer.apps.publish.store', $client), ['confirm' => true])->assertRedirect(route('password.confirm'));
    $this->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    $this->get(route('developer.apps.secret.confirm', $client))->assertOk()->assertSee('Regenerate client secret');
    $this->post(route('developer.apps.secret.store', $client))->assertSessionHasErrors('confirm');
    $this->get(route('developer.apps.publish.confirm', $client))->assertOk()->assertSee('Any verified Aether user');
    $this->post(route('developer.apps.publish.store', $client))->assertSessionHasErrors('confirm');
    expect($client->fresh()->secret)->toBe($oldHash)->and($client->fresh()->status)->toBe(OAuthClientStatus::Testing);
});

it('rotates the secret and immediately revokes all app credentials while preserving other apps', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner, true);
    $otherClient = oauthClientFixture($owner, true);
    $oldSecret = $client->plainSecret;
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, $owner, $client)))->assertOk()->json();
    $otherTokens = $this->postJson('/oauth/token', oauthExchange($otherClient, oauthCode($this, $owner, $otherClient)))->assertOk()->json();
    $pendingCode = oauthCode($this, $owner, $client);
    $this->withSession(['auth.password_confirmed_at' => now()->timestamp])
        ->post(route('developer.apps.secret.store', $client), ['confirm' => true])->assertRedirect(route('developer.apps.show', $client));
    $newSecret = Crypt::decryptString(session('developer.credentials.'.$client->id));
    expect(Hash::check($oldSecret, $client->fresh()->secret))->toBeFalse()
        ->and(Hash::check($newSecret, $client->fresh()->secret))->toBeTrue()
        ->and(oauthBearerWorks($tokens['access_token']))->toBeFalse()
        ->and(oauthBearerWorks($otherTokens['access_token']))->toBeTrue()
        ->and(Passport::authCode()->newQuery()->where('client_id', $client->id)->where('revoked', false)->count())->toBe(0)
        ->and(Passport::token()->newQuery()->where('client_id', $client->id)->where('revoked', false)->count())->toBe(0);
    $this->postJson('/oauth/token', ['grant_type' => 'refresh_token', 'client_id' => $client->id, 'client_secret' => $newSecret, 'refresh_token' => $tokens['refresh_token']])->assertStatus(400);
    $this->postJson('/oauth/token', [...oauthExchange($client, $pendingCode), 'client_secret' => $newSecret])->assertStatus(400);
    $this->get(route('developer.apps.show', $client))->assertOk()->assertSee($newSecret)->assertHeader('Cache-Control', 'no-store, private');
    $this->get(route('developer.apps.show', $client))->assertOk()->assertDontSee($newSecret);
    $client->plainSecret = $newSecret;
    $newCode = oauthCode($this, $owner, $client);
    $this->postJson('/oauth/token', [...oauthExchange($client, $newCode), 'client_secret' => $oldSecret])->assertStatus(401);
    $this->postJson('/oauth/token', oauthExchange($client, $newCode))->assertOk();
    expect(AuditLog::where('event', OAuthAuditEvent::ClientSecretRegenerated)->count())->toBe(1);
});

it('discards an obsolete one-time secret handoff after rotation in another session', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner, true);
    $oldSecret = $client->plainSecret;
    $this->actingAs($owner)->withSession(['auth.password_confirmed_at' => now()->timestamp])
        ->post(route('developer.apps.secret.store', $client), ['confirm' => true])->assertRedirect();
    $this->withSession(['developer.credentials.'.$client->id => Crypt::encryptString($oldSecret)])
        ->get(route('developer.apps.show', $client))->assertOk()->assertDontSee($oldSecret)->assertSee('The client secret is hidden.');
});

it('publishes only a testing owned web application and lets other verified users authorize', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $other = User::factory()->create();
    $client = oauthClientFixture($owner, true);
    $client->forceFill(['status' => OAuthClientStatus::Testing])->save();
    $this->actingAs($other)->get(oauthAuthorizeUrl(oauthParameters($client)))->assertForbidden();
    $this->actingAs($owner)->withSession(['auth.password_confirmed_at' => now()->timestamp])
        ->post(route('developer.apps.publish.store', $client), ['confirm' => true, 'first_party' => true])->assertRedirect(route('developer.apps.show', $client));
    expect($client->fresh()->status)->toBe(OAuthClientStatus::Live)->and($client->fresh()->first_party)->toBeFalse()
        ->and(AuditLog::sole()->event)->toBe(OAuthAuditEvent::ClientPublished);
    $this->post(route('developer.apps.publish.store', $client), ['confirm' => true])->assertForbidden();
    $this->actingAs($other)->get(oauthAuthorizeUrl(oauthParameters($client)))->assertOk()->assertSee('Allow');
});

it('blocks management of foreign revoked suspended and non-web applications', function (string $kind): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner, true);
    $client->forceFill(match ($kind) {
        'foreign' => ['owner_id' => User::factory()->create()->id],
        'revoked' => ['revoked' => true],
        'suspended' => ['status' => OAuthClientStatus::Suspended],
        'non-web' => ['app_type' => OAuthAppType::Machine],
    })->save();
    $this->actingAs($owner)->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    $this->get(route('developer.apps.edit', $client))->assertForbidden();
    $this->put(route('developer.apps.update', $client), webApplicationSettings())->assertForbidden();
    $this->get(route('developer.apps.secret.confirm', $client))->assertForbidden();
    $this->post(route('developer.apps.secret.store', $client), ['confirm' => true])->assertForbidden();
    $this->get(route('developer.apps.publish.confirm', $client))->assertForbidden();
    $this->post(route('developer.apps.publish.store', $client), ['confirm' => true])->assertForbidden();
})->with(['foreign', 'revoked', 'suspended', 'non-web']);

it('enforces removed permissions for existing access and refresh tokens after editing', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner, true);
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, $owner, $client, 'openid profile')))->assertOk()->json();
    $this->put(route('developer.apps.update', $client), webApplicationSettings(['redirect_urls' => $client->redirect_uris[0], 'scopes' => ['openid']]))->assertRedirect();
    expect(oauthBearerWorks($tokens['access_token']))->toBeFalse();
    $this->postJson('/oauth/token', ['grant_type' => 'refresh_token', 'client_id' => $client->id, 'client_secret' => $client->plainSecret, 'refresh_token' => $tokens['refresh_token']])->assertStatus(400);
});

it('cancels pending authorization codes when callback URLs are changed', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner, true);
    $code = oauthCode($this, $owner, $client);
    $this->put(route('developer.apps.update', $client), webApplicationSettings())->assertRedirect();
    $this->postJson('/oauth/token', oauthExchange($client, $code))->assertStatus(400);
    $this->get(oauthAuthorizeUrl(oauthParameters($client)))->assertStatus(401)->assertHeaderMissing('Location');
});
