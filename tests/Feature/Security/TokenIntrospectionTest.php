<?php

use App\Enums\OAuthAppType;
use App\Enums\OAuthClientStatus;
use App\Models\OAuthClient;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;

uses(RefreshDatabase::class);

function introspectionMachine(): OAuthClient
{
    $client = app(ClientRepository::class)->createClientCredentialsGrantClient('Pulse fixture');
    $client->forceFill(['status' => OAuthClientStatus::Live, 'app_type' => OAuthAppType::Machine, 'allowed_scopes' => ['stats:read']])->save();

    return $client;
}

function introspectionResource(OAuthClient $machine): OAuthClient
{
    $resource = oauthClientFixture(confidential: true);
    $resource->forceFill(['introspection_client_ids' => [$machine->getKey()]])->save();

    return $resource;
}

/** @return array<string, string> */
function introspectionCredentials(OAuthClient $resource, string $token): array
{
    return ['client_id' => $resource->getKey(), 'client_secret' => $resource->plainSecret, 'token' => $token];
}

it('allows only the explicitly authorized resource to inspect a machine token', function (): void {
    $machine = introspectionMachine();
    $resource = introspectionResource($machine);
    $token = $this->postJson('/oauth/token', ['client_id' => $machine->getKey(), 'client_secret' => $machine->plainSecret, 'grant_type' => 'client_credentials', 'scope' => 'stats:read'])->assertOk()->json('access_token');
    $response = $this->postJson('/oauth/introspect', introspectionCredentials($resource, $token))->assertOk()
        ->assertJsonPath('active', true)->assertJsonPath('client_id', $machine->getKey())
        ->assertJsonPath('scope', 'stats:read')->assertJsonPath('resource_client_id', $resource->getKey())
        ->assertJsonPath('client_type', 'm2m')->assertJsonPath('grant_type', 'client_credentials')
        ->assertHeader('Cache-Control', 'no-store, private');
    expect($response->json())->not->toHaveKeys(['sub', 'username', 'email', 'token', 'client_secret']);
    $otherMachine = introspectionMachine();
    $otherResource = introspectionResource($otherMachine);
    $this->postJson('/oauth/introspect', introspectionCredentials($otherResource, $token))->assertExactJson(['active' => false]);
});

it('supports Basic authentication and rejects mixed or incorrect credentials', function (): void {
    $machine = introspectionMachine();
    $resource = introspectionResource($machine);
    $basic = ['Authorization' => 'Basic '.base64_encode($resource->getKey().':'.$resource->plainSecret)];
    $this->postJson('/oauth/introspect', ['token' => 'invalid'], $basic)->assertOk()->assertExactJson(['active' => false]);
    $this->postJson('/oauth/introspect', introspectionCredentials($resource, 'invalid'), $basic)->assertStatus(400);
    $this->postJson('/oauth/introspect', ['token' => 'invalid'])->assertUnauthorized();
    $this->postJson('/oauth/introspect', [...introspectionCredentials($resource, 'invalid'), 'client_secret' => 'incorrect'])->assertUnauthorized();
    $this->getJson('/oauth/introspect')->assertStatus(405);
});

it('requires explicit permission even with valid confidential client credentials', function (): void {
    $resource = oauthClientFixture(confidential: true);
    $this->postJson('/oauth/introspect', introspectionCredentials($resource, 'invalid'))->assertUnauthorized()->assertJsonPath('error', 'access_denied');
    $public = oauthClientFixture();
    $this->postJson('/oauth/introspect', ['client_id' => $public->getKey(), 'token' => 'invalid'])->assertUnauthorized();
});

it('returns inactive for revoked expired malformed or tampered access tokens', function (string $condition): void {
    $machine = introspectionMachine();
    $resource = introspectionResource($machine);
    $token = $this->postJson('/oauth/token', ['client_id' => $machine->getKey(), 'client_secret' => $machine->plainSecret, 'grant_type' => 'client_credentials', 'scope' => 'stats:read'])->assertOk()->json('access_token');
    if ($condition === 'revoked') {
        Passport::token()->newQuery()->firstOrFail()->revoke();
    } elseif ($condition === 'expired') {
        Passport::token()->newQuery()->update(['expires_at' => now()->subMinute()]);
    } elseif ($condition === 'tampered') {
        $parts = explode('.', $token);
        $parts[2][0] = $parts[2][0] === 'a' ? 'b' : 'a';
        $token = implode('.', $parts);
    } else {
        $token = 'malformed-token';
    }
    $this->postJson('/oauth/introspect', introspectionCredentials($resource, $token))->assertOk()->assertExactJson(['active' => false]);
})->with(['revoked', 'expired', 'tampered', 'malformed']);

it('rechecks machine lifecycle scopes type and resource permission', function (string $condition): void {
    $machine = introspectionMachine();
    $resource = introspectionResource($machine);
    $token = $this->postJson('/oauth/token', ['client_id' => $machine->getKey(), 'client_secret' => $machine->plainSecret, 'grant_type' => 'client_credentials', 'scope' => 'stats:read'])->assertOk()->json('access_token');
    if ($condition === 'permission') {
        $resource->forceFill(['introspection_client_ids' => []])->save();
        $this->postJson('/oauth/introspect', introspectionCredentials($resource, $token))->assertUnauthorized();

        return;
    }
    $machine->forceFill(match ($condition) {
        'suspended' => ['status' => OAuthClientStatus::Suspended],
        'scopes' => ['allowed_scopes' => []],
        'type' => ['app_type' => OAuthAppType::Web],
        'grant' => ['grant_types' => ['authorization_code']],
    })->save();
    $this->postJson('/oauth/introspect', introspectionCredentials($resource, $token))->assertExactJson(['active' => false]);
})->with(['suspended', 'scopes', 'type', 'grant', 'permission']);

it('never reveals user or refresh token metadata to a machine resource', function (): void {
    $client = oauthClientFixture(confidential: true);
    $resource = introspectionResource($client);
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, User::factory()->create(), $client)))->assertOk();
    foreach (['access_token', 'refresh_token'] as $field) {
        $this->postJson('/oauth/introspect', introspectionCredentials($resource, $tokens->json($field)))->assertExactJson(['active' => false]);
    }
});

it('rejects malformed protocol input without reflecting or flashing it', function (): void {
    $this->postJson('/oauth/introspect', ['token' => ['private-token'], 'client_secret' => ['secret']])->assertStatus(400)->assertDontSee('private-token');
    $this->postJson('/oauth/introspect?token=private-token', [])->assertStatus(400)->assertDontSee('private-token');
});

it('rate limits introspection separately from issuance', function (): void {
    $resource = introspectionResource(introspectionMachine());
    for ($attempt = 0; $attempt < 60; $attempt++) {
        $this->postJson('/oauth/introspect', introspectionCredentials($resource, 'invalid'))->assertOk();
    }
    $this->postJson('/oauth/introspect', introspectionCredentials($resource, 'invalid'))->assertStatus(429);
});
