<?php

use App\Enums\OAuthAppType;
use App\Enums\OAuthAuditEvent;
use App\Enums\OAuthClientStatus;
use App\Models\AuditLog;
use App\Models\OAuthClient;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Hash;

uses(RefreshDatabase::class);

function webRegistrationData(array $overrides = []): array
{
    return array_replace([
        'name' => 'My web application', 'homepage_url' => 'https://client.example',
        'redirect_urls' => "https://client.example/callback\nhttp://localhost:8765/callback",
        'scopes' => ['openid', 'profile', 'email'],
    ], $overrides);
}

it('creates a testing owned confidential web client and shows its secret once', function (): void {
    $user = User::factory()->create(['is_developer' => true]);
    $other = User::factory()->create();
    $this->actingAs($user)->get('/developer/apps/create')->assertOk()->assertSee('Register a web application')->assertDontSee('stats:read');
    $response = $this->post('/developer/apps', webRegistrationData([
        'owner_id' => $other->id, 'owner_type' => $other->getMorphClass(),
        'status' => 'live', 'app_type' => 'm2m', 'first_party' => true,
        'grant_types' => ['client_credentials'], 'introspection_client_ids' => ['privileged'],
        'allowed_scopes' => ['stats:read'], 'secret' => 'attacker-secret',
    ]));
    $client = OAuthClient::sole();
    $response->assertRedirect(route('developer.apps.show', $client))->assertHeader('Cache-Control', 'no-store, private');
    $encrypted = session('developer.credentials.'.$client->id);
    $secret = Crypt::decryptString($encrypted);
    expect($encrypted)->not->toContain($secret)
        ->and(Hash::check($secret, $client->secret))->toBeTrue()
        ->and($client->secret)->not->toBe($secret)
        ->and($client->owner_id)->toBe($user->id)
        ->and($client->owner_type)->toBe($user->getMorphClass())
        ->and($client->status)->toBe(OAuthClientStatus::Testing)
        ->and($client->app_type)->toBe(OAuthAppType::Web)
        ->and($client->first_party)->toBeFalse()
        ->and($client->introspection_client_ids)->toBeNull()
        ->and($client->grant_types)->toBe(['authorization_code', 'refresh_token'])
        ->and($client->allowed_scopes)->toBe(['openid', 'profile', 'email'])
        ->and($client->redirect_uris)->toBe(['https://client.example/callback', 'http://localhost:8765/callback'])
        ->and($client->acceptsUser($user))->toBeTrue()
        ->and($client->acceptsUser($other))->toBeFalse()
        ->and(AuditLog::sole()->event)->toBe(OAuthAuditEvent::ClientCreated);
    $this->get(route('developer.apps.show', $client))->assertOk()->assertSee($secret)
        ->assertSee('Save your client secret now.')->assertHeader('Cache-Control', 'no-store, private');
    expect(session('developer.credentials.'.$client->id))->toBeNull();
    $this->get(route('developer.apps.show', $client))->assertOk()->assertDontSee($secret)
        ->assertSee('The client secret is hidden.');
    $this->get('/developer/apps')->assertOk()->assertSee('My web application')->assertDontSee($secret);
});

it('requires verified developer access for registration', function (): void {
    $this->get('/developer/apps/create')->assertRedirect('/login');
    $this->post('/developer/apps', webRegistrationData())->assertRedirect('/login');
    $this->actingAs(User::factory()->unverified()->create(['is_developer' => true]))
        ->post('/developer/apps', webRegistrationData())->assertRedirect('/email/verify');
    $this->actingAs(User::factory()->create())->get('/developer/apps/create')->assertForbidden();
    $this->post('/developer/apps', webRegistrationData())->assertForbidden();
    expect(OAuthClient::count())->toBe(0);
});

it('does not allow another developer to read an app or consume its credential handoff', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $other = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner, true);
    $encrypted = Crypt::encryptString('test-one-time-secret');
    $this->actingAs($other)->withSession(['developer.credentials.'.$client->id => $encrypted])
        ->get(route('developer.apps.show', $client))->assertForbidden();
    expect(session('developer.credentials.'.$client->id))->toBe($encrypted);
    $this->get('/developer/apps/not-a-client')->assertNotFound();
});

it('rejects unsafe callback URLs without creating clients', function (string $url): void {
    $user = User::factory()->create(['is_developer' => true]);
    $this->actingAs($user)->post('/developer/apps', webRegistrationData(['redirect_urls' => $url]))
        ->assertRedirect('/developer/apps/create')->assertSessionHasErrors('redirect_uris.0');
    expect(OAuthClient::count())->toBe(0);
})->with([
    'wildcard' => 'https://client.example/*',
    'encoded wildcard' => 'https://client.example/%2A',
    'remote HTTP' => 'http://client.example/callback',
    'localhost suffix' => 'http://localhost.attacker.example/callback',
    'private network HTTP' => 'http://192.168.1.5/callback',
    'credentials' => 'https://user:password@client.example/callback',
    'fragment' => 'https://client.example/callback#fragment',
    'partial' => '/callback',
    'non-web' => 'javascript:alert(1)',
]);

it('accepts exact localhost and loopback development callbacks', function (string $url): void {
    $this->actingAs(User::factory()->create(['is_developer' => true]))
        ->post('/developer/apps', webRegistrationData(['redirect_urls' => $url, 'homepage_url' => null]))->assertRedirect();
    expect(OAuthClient::sole()->redirect_uris)->toBe([$url]);
})->with(['http://localhost:8765/callback', 'http://127.0.0.1:8765/callback', 'http://[::1]:8765/callback']);

it('rejects malformed inputs and privileged scopes', function (array $attributes, string $field): void {
    $this->actingAs(User::factory()->create(['is_developer' => true]))
        ->post('/developer/apps', webRegistrationData($attributes))->assertSessionHasErrors($field);
    expect(OAuthClient::count())->toBe(0);
})->with([
    'name array' => [['name' => []], 'name'],
    'name missing' => [['name' => ''], 'name'],
    'callback array' => [['redirect_urls' => []], 'redirect_urls'],
    'duplicate callback' => [['redirect_urls' => "https://client.example/callback\nhttps://client.example/callback"], 'redirect_uris.0'],
    'too many callbacks' => [['redirect_urls' => implode("\n", array_map(fn (int $number): string => 'https://client.example/callback'.$number, range(1, 11)))], 'redirect_uris'],
    'privileged scope' => [['scopes' => ['openid', 'stats:read']], 'scopes.1'],
    'unknown scope' => [['scopes' => ['openid', '*']], 'scopes.1'],
    'missing sign-in' => [['scopes' => ['profile']], 'scopes'],
    'scope array' => [['scopes' => [['openid']]], 'scopes.0'],
    'insecure homepage' => [['homepage_url' => 'http://client.example'], 'homepage_url'],
]);

it('escapes application metadata on the details page', function (): void {
    $user = User::factory()->create(['is_developer' => true]);
    $this->actingAs($user)->post('/developer/apps', webRegistrationData(['name' => '<script>alert(1)</script>']))->assertRedirect();
    $this->get(route('developer.apps.show', OAuthClient::sole()))->assertOk()
        ->assertSee('&lt;script&gt;alert(1)&lt;/script&gt;', false)->assertDontSee('<script>alert(1)</script>', false);
});

it('integrates registered testing clients with owner-only exact-redirect PKCE authorization', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $this->actingAs($owner)->post('/developer/apps', webRegistrationData())->assertRedirect();
    $client = OAuthClient::sole();
    $client->plainSecret = Crypt::decryptString(session('developer.credentials.'.$client->id));
    $this->actingAs(User::factory()->create())->get(oauthAuthorizeUrl(oauthParameters($client)))->assertForbidden();
    $this->actingAs($owner)->get(oauthAuthorizeUrl([...oauthParameters($client), 'redirect_uri' => 'https://client.example/callback/extra']))->assertStatus(401)->assertHeaderMissing('Location');
    $code = oauthCode($this, $owner, $client);
    $this->postJson('/oauth/token', oauthExchange($client, $code))->assertOk()->assertJsonStructure(['access_token', 'id_token']);
    $this->postJson('/oauth/token', ['grant_type' => 'client_credentials', 'client_id' => $client->id, 'client_secret' => $client->plainSecret, 'scope' => 'stats:read'])->assertStatus(400)->assertJsonPath('error', 'unauthorized_client');
});
