<?php

use App\Actions\Developer\DeleteApplication;
use App\Actions\Developer\PublishApplication;
use App\Actions\Developer\RegenerateApplicationSecret;
use App\Actions\Developer\UpdateApplication;
use App\Enums\OAuthAppType;
use App\Enums\OAuthAuditEvent;
use App\Enums\OAuthClientStatus;
use App\Models\AuditLog;
use App\Models\OAuthClient;
use App\Models\User;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;

uses(RefreshDatabase::class);

/** @return array<string, mixed> */
function machineRegistrationData(array $overrides = []): array
{
    return array_replace(['app_type' => 'm2m', 'name' => 'Report service', 'homepage_url' => 'https://service.example'], $overrides);
}

/** @return array<string, string> */
function machineTokenData(OAuthClient $client, string $secret, string $scope = 'stats:read'): array
{
    return ['grant_type' => 'client_credentials', 'client_id' => $client->id, 'client_secret' => $secret, 'scope' => $scope];
}

it('registers an owned testing machine with no permissions and consumes its secret once', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $this->actingAs($owner)->get(route('developer.apps.machine.create'))->assertOk()->assertSee('Machine application')
        ->assertDontSee('name="redirect_urls"', false)->assertDontSee('name="scopes[]"', false);
    $this->post(route('developer.apps.store'), machineRegistrationData([
        'owner_id' => 999, 'owner_type' => 'Other', 'status' => 'live', 'first_party' => true,
        'allowed_scopes' => ['stats:read'], 'introspection_client_ids' => ['injected'],
        'grant_types' => ['authorization_code', 'refresh_token'], 'secret' => 'injected', 'redirect_uris' => ['https://injected.example'],
    ]))->assertRedirect();
    $client = OAuthClient::sole();
    $handoff = session('developer.credentials.'.$client->id);
    $secret = Crypt::decryptString($handoff);
    expect($client->app_type)->toBe(OAuthAppType::Machine)->and($client->status)->toBe(OAuthClientStatus::Testing)
        ->and($client->owner_id)->toBe($owner->id)->and($client->owner_type)->toBe($owner->getMorphClass())
        ->and($client->grant_types)->toBe(['client_credentials'])->and($client->redirect_uris)->toBe([])
        ->and($client->allowed_scopes)->toBe([])->and($client->first_party)->toBeFalse()->and($client->introspection_client_ids)->toBeNull()
        ->and($client->confidential())->toBeTrue()->and(Hash::check($secret, $client->secret))->toBeTrue()
        ->and($handoff)->not->toContain($secret)->and(AuditLog::sole()->event)->toBe(OAuthAuditEvent::ClientCreated);
    $this->get(route('developer.apps.show', $client))->assertOk()->assertSee($secret)
        ->assertSee('Approved API permissions')->assertSee('No permissions approved.')->assertSee('Connect your service')
        ->assertSee('grant_type=client_credentials')->assertSee('Regenerate secret')->assertDontSee('Go live')->assertDontSee('Callback URLs')
        ->assertDontSee('Use an OpenID Connect client library')->assertHeader('Cache-Control', 'no-store, private');
    expect(session('developer.credentials.'.$client->id))->toBeNull();
    $this->get(route('developer.apps.show', $client))->assertOk()->assertDontSee($secret);
    $this->get(route('developer.apps.index'))->assertOk()->assertSee('Report service')->assertDontSee($secret);
    $this->postJson('/oauth/token', machineTokenData($client, $secret))->assertStatus(400)->assertJsonPath('error', 'unauthorized_client');
});

it('requires verified developer registration and protects the machine page', function (): void {
    $this->get(route('developer.apps.machine.create'))->assertRedirect('/login');
    $this->actingAs(User::factory()->unverified()->create(['is_developer' => true]))->get(route('developer.apps.machine.create'))->assertRedirect('/email/verify');
    $this->post(route('developer.apps.store'), machineRegistrationData())->assertRedirect('/email/verify');
    $this->actingAs(User::factory()->create())->get(route('developer.apps.machine.create'))->assertForbidden();
    $this->post(route('developer.apps.store'), machineRegistrationData())->assertForbidden();
    expect(OAuthClient::count())->toBe(0);
});

it('rejects owner requested machine scopes callbacks and malformed fields', function (array $overrides, string $field): void {
    $this->actingAs(User::factory()->create(['is_developer' => true]))
        ->post(route('developer.apps.store'), machineRegistrationData($overrides))
        ->assertRedirect(route('developer.apps.machine.create'))->assertSessionHasErrors($field);
    expect(OAuthClient::count())->toBe(0);
})->with([
    [['scopes' => ['stats:read']], 'scopes'],
    [['scopes' => ['openid']], 'scopes'],
    [['redirect_urls' => 'https://service.example/callback'], 'redirect_urls'],
    [['name' => ['unexpected']], 'name'],
    [['homepage_url' => 'http://service.example'], 'homepage_url'],
]);

it('keeps approved machine permissions and credential type outside owner settings', function (): void {
    Storage::fake('local');
    $owner = User::factory()->create(['is_developer' => true]);
    $this->actingAs($owner)->post(route('developer.apps.store'), machineRegistrationData());
    $client = OAuthClient::sole();
    // Simulate a separately approved operator grant; portal input must never make this change.
    $client->forceFill(['allowed_scopes' => ['stats:read'], 'status' => OAuthClientStatus::Live])->save();
    $secretHash = $client->secret;
    $this->get(route('developer.apps.edit', $client))->assertOk()->assertDontSee('name="scopes[]"', false)->assertDontSee('name="redirect_urls"', false);
    $this->put(route('developer.apps.update', $client), [
        'name' => 'Updated machine', 'homepage_url' => 'https://updated.example', 'logo' => UploadedFile::fake()->image('logo.png'),
        'app_type' => 'web', 'allowed_scopes' => ['openid'], 'introspection_client_ids' => ['injected'],
        'status' => 'testing', 'first_party' => true, 'grant_types' => ['authorization_code'], 'owner_id' => 999,
    ])->assertSessionHasNoErrors()->assertRedirect(route('developer.apps.show', $client));
    $client->refresh();
    expect($client->name)->toBe('Updated machine')->and($client->allowed_scopes)->toBe(['stats:read'])
        ->and($client->status)->toBe(OAuthClientStatus::Live)->and($client->app_type)->toBe(OAuthAppType::Machine)
        ->and($client->owner_id)->toBe($owner->id)->and($client->secret)->toBe($secretHash)
        ->and($client->first_party)->toBeFalse()->and($client->introspection_client_ids)->toBeNull()
        ->and($client->grant_types)->toBe(['client_credentials'])->and($client->redirect_uris)->toBe([]);
    Storage::disk('local')->assertExists($client->logo_path);
    $this->get(route('passport.client.logo', $client))->assertOk();
    $this->put(route('developer.apps.update', $client), ['name' => 'Invalid', 'scopes' => ['stats:read']])->assertSessionHasErrors('scopes');
});

it('never allows owner publication or activation through the action or HTTP routes', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $this->actingAs($owner)->post(route('developer.apps.store'), machineRegistrationData());
    $client = OAuthClient::sole();
    $this->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    $this->get(route('developer.apps.publish.confirm', $client))->assertForbidden();
    $this->post(route('developer.apps.publish.store', $client), ['confirm' => true])->assertForbidden();
    expect(fn () => app(PublishApplication::class)->handle($client))->toThrow(AuthorizationException::class);
    $this->put(route('developer.apps.update', $client), ['name' => 'Still testing', 'status' => 'live', 'allowed_scopes' => ['stats:read']])->assertSessionHasNoErrors();
    expect($client->fresh()->status)->toBe(OAuthClientStatus::Testing)->and($client->fresh()->allowed_scopes)->toBe([]);
});

it('issues only approved machine tokens and still requires resource specific permission', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $this->actingAs($owner)->post(route('developer.apps.store'), machineRegistrationData());
    $client = OAuthClient::sole();
    $secret = Crypt::decryptString(session('developer.credentials.'.$client->id));
    $this->postJson('/oauth/token', machineTokenData($client, $secret))->assertStatus(400)->assertJsonPath('error', 'unauthorized_client');
    $client->forceFill(['status' => OAuthClientStatus::Live, 'allowed_scopes' => ['stats:read']])->save();
    $tokens = $this->postJson('/oauth/token', machineTokenData($client, $secret))->assertOk()->json();
    expect($tokens)->not->toHaveKeys(['refresh_token', 'id_token']);
    $this->postJson('/oauth/token', machineTokenData($client, $secret, 'openid'))->assertStatus(400);
    $this->postJson('/oauth/token', [...machineTokenData($client, $secret), 'grant_type' => 'authorization_code', 'code' => 'invalid'])->assertStatus(400);
    $resource = oauthClientFixture(confidential: true);
    $request = ['client_id' => $resource->id, 'client_secret' => $resource->plainSecret, 'token' => $tokens['access_token']];
    $this->postJson('/oauth/introspect', $request)->assertUnauthorized();
    $resource->forceFill(['introspection_client_ids' => [$client->id]])->save();
    $this->postJson('/oauth/introspect', $request)->assertOk()->assertJsonPath('active', true)->assertJsonPath('scope', 'stats:read');
    $client->forceFill(['allowed_scopes' => []])->save();
    $this->postJson('/oauth/introspect', $request)->assertExactJson(['active' => false]);
});

it('requires confirmation and revokes machine tokens immediately on secret rotation', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $this->actingAs($owner)->post(route('developer.apps.store'), machineRegistrationData());
    $client = OAuthClient::sole();
    $oldSecret = Crypt::decryptString(session('developer.credentials.'.$client->id));
    $client->forceFill(['status' => OAuthClientStatus::Live, 'allowed_scopes' => ['stats:read']])->save();
    $tokens = $this->postJson('/oauth/token', machineTokenData($client, $oldSecret))->assertOk()->json();
    $this->post(route('developer.apps.secret.store', $client), ['confirm' => true])->assertRedirect(route('password.confirm'));
    $this->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    $this->get(route('developer.apps.secret.confirm', $client))->assertOk()->assertSee('Update your service with the replacement secret.');
    $this->post(route('developer.apps.secret.store', $client))->assertSessionHasErrors('confirm');
    $this->post(route('developer.apps.secret.store', $client), ['confirm' => true])->assertRedirect();
    $replacement = Crypt::decryptString(session('developer.credentials.'.$client->id));
    expect(Hash::check($replacement, $client->fresh()->secret))->toBeTrue()->and(oauthBearerWorks($tokens['access_token']))->toBeFalse();
    $this->postJson('/oauth/token', machineTokenData($client, $oldSecret))->assertStatus(401);
    $this->postJson('/oauth/token', machineTokenData($client, $replacement))->assertOk();
    $this->withSession(['developer.credentials.'.$client->id => Crypt::encryptString($oldSecret)])
        ->get(route('developer.apps.show', $client))->assertOk()->assertDontSee($oldSecret)->assertDontSee($replacement);
    expect(AuditLog::where('event', OAuthAuditEvent::ClientSecretRegenerated)->count())->toBe(1);
});

it('retains deleted machine records and permanently revokes their tokens', function (OAuthClientStatus $status): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $this->actingAs($owner)->post(route('developer.apps.store'), machineRegistrationData());
    $client = OAuthClient::sole();
    $secret = Crypt::decryptString(session('developer.credentials.'.$client->id));
    $client->forceFill(['status' => OAuthClientStatus::Live, 'allowed_scopes' => ['stats:read']])->save();
    $tokens = $this->postJson('/oauth/token', machineTokenData($client, $secret))->assertOk()->json();
    $client->forceFill(['status' => $status])->save();
    $this->post(route('developer.apps.delete.store', $client), ['confirm' => true])->assertRedirect(route('password.confirm'));
    $this->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    $this->get(route('developer.apps.delete.confirm', $client))->assertOk()->assertSee('all access tokens for this service will be invalidated');
    $this->post(route('developer.apps.delete.store', $client))->assertSessionHasErrors('confirm');
    $this->post(route('developer.apps.delete.store', $client), ['confirm' => true])->assertRedirect(route('developer.apps.index'));
    expect($client->fresh()->revoked)->toBeTrue()->and(oauthBearerWorks($tokens['access_token']))->toBeFalse()
        ->and(session('developer.credentials.'.$client->id))->toBeNull()->and(AuditLog::where('event', OAuthAuditEvent::ClientDeleted)->count())->toBe(1);
    $this->get(route('developer.apps.show', $client))->assertForbidden();
    $this->get(route('developer.apps.index'))->assertDontSee('Report service');
    $this->postJson('/oauth/token', machineTokenData($client, $secret))->assertStatus(401);
})->with(OAuthClientStatus::cases());

it('rechecks machine ownership and lifecycle under the lock for all owner mutations', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $this->actingAs($owner)->post(route('developer.apps.store'), machineRegistrationData());
    $client = OAuthClient::sole();
    $this->actingAs(User::factory()->create(['is_developer' => true]))->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    $this->get(route('developer.apps.show', $client))->assertForbidden();
    $this->put(route('developer.apps.update', $client), ['name' => 'Foreign'])->assertForbidden();
    $this->post(route('developer.apps.secret.store', $client), ['confirm' => true])->assertForbidden();
    $this->post(route('developer.apps.delete.store', $client), ['confirm' => true])->assertForbidden();
    $this->actingAs($owner);
    $client->newQuery()->whereKey($client->id)->update(['status' => OAuthClientStatus::Suspended]);
    expect(fn () => app(UpdateApplication::class)->handle($client, ['name' => 'Stale']))->toThrow(AuthorizationException::class);
    expect(fn () => app(RegenerateApplicationSecret::class)->handle($client))->toThrow(AuthorizationException::class);
    $client->newQuery()->whereKey($client->id)->update(['owner_id' => User::factory()->create()->id]);
    expect(fn () => app(DeleteApplication::class)->handle($client))->toThrow(AuthorizationException::class);
});

it('restores suspended machine clients to blocked testing without owner activation', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $this->actingAs($owner)->post(route('developer.apps.store'), machineRegistrationData());
    $client = OAuthClient::sole();
    $secret = Crypt::decryptString(session('developer.credentials.'.$client->id));
    $client->forceFill(['status' => OAuthClientStatus::Live, 'allowed_scopes' => ['stats:read']])->save();
    $tokens = $this->postJson('/oauth/token', machineTokenData($client, $secret))->assertOk()->json();
    $admin = User::factory()->create(['is_admin' => true, 'two_factor_secret' => encrypt('fixture'), 'two_factor_confirmed_at' => now()]);
    $this->actingAs($admin)->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    $this->post(route('admin.apps.suspend', $client), ['confirm' => true])->assertRedirect();
    expect(oauthBearerWorks($tokens['access_token']))->toBeFalse();
    $this->get(route('admin.apps.show', $client))->assertOk()->assertSee('Machine API permissions and activation require administrator approval.');
    $this->get(route('admin.apps.restore.confirm', $client))->assertOk()->assertSee('Token issuance remains blocked');
    $this->post(route('admin.apps.restore', $client), ['confirm' => true])->assertRedirect();
    expect($client->fresh()->status)->toBe(OAuthClientStatus::Testing)->and(oauthBearerWorks($tokens['access_token']))->toBeFalse();
    $this->postJson('/oauth/token', machineTokenData($client, $secret))->assertStatus(400)->assertJsonPath('error', 'unauthorized_client');
    $this->actingAs($owner)->post(route('developer.apps.publish.store', $client), ['confirm' => true])->assertForbidden();
});
