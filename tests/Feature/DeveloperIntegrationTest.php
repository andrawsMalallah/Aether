<?php

use App\Enums\OAuthAppType;
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
        ->assertSee('Laravel example: sign in and local logout')
        ->assertDontSee('Vue Browser example: sign in, refresh and local logout')
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
        ->assertSee('Vue Browser example: sign in, refresh and local logout')
        ->assertDontSee('Laravel example: sign in and local logout')
        ->assertDontSee('Keep your client secret in your server environment');
});

it('renders the actual Vue example files as escaped source on Browser details only', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner);
    $response = $this->actingAs($owner)->get(route('developer.apps.show', $client));
    $response->assertOk()->assertHeader('Cache-Control', 'no-store, private')
        ->assertSee('npm install --save-exact openid-client@6.8.8')
        ->assertSee('This profile example requires all three scopes.')
        ->assertSee('this guide grants no new origin access')
        ->assertSee('VITE_AETHER_CLIENT_ID=<client ID from this page>')
        ->assertSee('credentials: "omit"')->assertSee('protocol.None()')
        ->assertSee('expectedNonce: attempt.nonce')->assertSee('expectedState: attempt.state')
        ->assertSee('enableNonRepudiationChecks')->assertSee('src/auth.js')->assertSee('src/App.vue');

    foreach (['auth.js', 'App.vue', 'example.css'] as $filename) {
        $response->assertSee(file_get_contents(resource_path('examples/browser/'.$filename)));
    }
    $response->assertDontSee('<script setup>', false)->assertDontSee('VITE_AETHER_CLIENT_SECRET');
});

it('renders copyable Laravel examples without executing their Blade or exposing app credentials', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner, true);
    $response = $this->actingAs($owner)->get(route('developer.apps.show', $client));

    $response->assertOk()->assertSee('AETHER_CLIENT_SECRET=<your private client secret>')
        ->assertSee('ShouldBeEncrypted')->assertSee('aether_attempt_expires')
        ->assertSee('@csrf')->assertSee('{{ $'."identity['subject'] }}")
        ->assertSee('composer audit')->assertSee('php artisan queue:work')
        ->assertDontSee($client->plainSecret)->assertDontSee($client->secret);

    preg_match_all('/<pre[^>]*><code>(.*?)<\/code><\/pre>/s', $response->getContent(), $matches);
    $phpExamples = array_values(array_filter(array_map(
        fn (string $snippet): string => html_entity_decode($snippet, ENT_QUOTES | ENT_HTML5, 'UTF-8'),
        $matches[1],
    ), fn (string $snippet): bool => str_starts_with($snippet, '<?php')));

    expect($phpExamples)->toHaveCount(5);
    foreach ($phpExamples as $snippet) {
        expect(token_get_all($snippet, TOKEN_PARSE))->not->toBeEmpty();
    }
});

it('labels unavailable web integration settings as reference only', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner, true);
    $client->forceFill(['status' => OAuthClientStatus::Suspended])->save();
    $this->actingAs($owner)->get(route('developer.apps.show', $client))->assertOk()
        ->assertSee('This application is unavailable.');
});

it('shows escaped Machine command source only to its verified developer owner', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner, true);
    $client->forceFill([
        'app_type' => OAuthAppType::Machine, 'grant_types' => ['client_credentials'],
        'redirect_uris' => [], 'allowed_scopes' => ['stats:read'],
    ])->save();
    $response = $this->actingAs($owner)->get(route('developer.apps.show', $client));
    $response->assertOk()->assertHeader('Cache-Control', 'no-store, private')
        ->assertSee('Laravel Machine example: request, call an API and revoke')
        ->assertSee('php artisan aether:stats')->assertSee('This guide does not grant scopes')
        ->assertDontSee('Laravel example: sign in and local logout')
        ->assertDontSee('Vue Browser example: sign in, refresh and local logout')
        ->assertDontSee($client->plainSecret)->assertDontSee($client->secret);
    foreach (['aether-machine.php', 'ReadAetherStats.php'] as $filename) {
        $source = file_get_contents(resource_path('examples/machine/'.$filename));
        $response->assertSee($source);
        expect(token_get_all($source, TOKEN_PARSE))->not->toBeEmpty();
    }
    $this->actingAs(User::factory()->create(['is_developer' => true]))
        ->get(route('developer.apps.show', $client))->assertForbidden()
        ->assertDontSee('Laravel Machine example: request, call an API and revoke');
});
