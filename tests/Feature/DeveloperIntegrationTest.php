<?php

use App\Enums\OAuthClientStatus;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;

uses(RefreshDatabase::class);

it('shows saved web integration settings using the canonical issuer without credentials or privileged capabilities', function (): void {
    config(['oidc.issuer' => 'https://identity.example']);
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner, true);
    $client->forceFill(['allowed_scopes' => ['openid', 'email'], 'redirect_uris' => ['https://client.example/callback?next=%2Fnotes&source=login']])->save();

    $response = $this->actingAs($owner)->get(route('developer.apps.show', $client));
    $response->assertOk()->assertHeader('Cache-Control', 'no-store, private')
        ->assertSee('Connect your application')->assertSee($client->id)
        ->assertSee('https://identity.example/.well-known/openid-configuration')
        ->assertSee('https://identity.example/oauth/authorize')->assertSee('https://identity.example/oauth/token')
        ->assertSee('https://identity.example/oauth/userinfo')->assertSee('https://identity.example/.well-known/jwks.json')
        ->assertSee('https://identity.example/oauth/revoke')->assertSee('openid email')
        ->assertSee($client->redirect_uris[0])->assertSee('code_challenge_method=S256')
        ->assertSee('The client secret is hidden.')->assertDontSee($client->plainSecret)
        ->assertDontSee($client->secret)->assertDontSee('stats:read')->assertDontSee('/oauth/introspect')
        ->assertDontSee('client_credentials')->assertDontSee('openid profile email');

    $client->forceFill(['allowed_scopes' => ['openid'], 'redirect_uris' => ['https://client.example/new-callback']])->save();
    $this->get(route('developer.apps.show', $client))->assertOk()->assertSee('https://client.example/new-callback')
        ->assertDontSee('openid email')->assertDontSee('source=login');
});

it('keeps integration instructions behind verified owner access and supports browser clients', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner, true);
    $this->get(route('developer.apps.show', $client))->assertRedirect('/login');
    $this->actingAs(User::factory()->unverified()->create(['is_developer' => true]))
        ->get(route('developer.apps.show', $client))->assertRedirect('/email/verify');
    $this->actingAs(User::factory()->create(['is_developer' => true]))
        ->get(route('developer.apps.show', $client))->assertForbidden()->assertDontSee('Connect your application');
    $publicClient = oauthClientFixture($owner);
    $this->actingAs($owner)->get(route('developer.apps.show', $publicClient))->assertOk()->assertSee('Connect your application')
        ->assertSee('This public client has no secret')->assertSee('Origin configuration is managed separately.')
        ->assertDontSee('Keep your client secret in your server environment');
});

it('labels unavailable web integration settings as reference only', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner, true);
    $client->forceFill(['status' => OAuthClientStatus::Suspended])->save();
    $this->actingAs($owner)->get(route('developer.apps.show', $client))->assertOk()
        ->assertSee('This application is unavailable.');
});
