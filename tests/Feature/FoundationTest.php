<?php

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\Vite;
use Illuminate\Support\Str;
use Laravel\Passport\Passport;

uses(RefreshDatabase::class);

it('issues OAuth credentials without local signing key files', function (): void {
    $originalPath = Passport::$keyPath;
    Passport::loadKeysFrom(storage_path('framework/no-test-keys-'.Str::uuid()));
    try {
        expect(file_exists(Passport::keyPath('oauth-private.key')))->toBeFalse();
        $user = User::factory()->create();
        $client = oauthClientFixture($user, true);
        $code = oauthCode($this, $user, $client);
        $this->postJson('/oauth/token', oauthExchange($client, $code))->assertOk()->assertJsonStructure(['access_token', 'id_token']);
    } finally {
        Passport::$keyPath = $originalPath;
    }
});

it('serves the Aether welcome page with compiled assets', function (): void {
    $this->get('/')
        ->assertOk()
        ->assertSee('AETHER')
        ->assertSee('One identity, every application.')
        ->assertSee('Create an account')
        ->assertSee('Sign in')
        ->assertDontSee('Welcome back.')
        ->assertDontSee('Open your account')
        ->assertDontSee('tailwind');
});

it('uses the shared local brand image for the page logo and favicon', function (string $path): void {
    $brandAssetUrl = Vite::asset('resources/images/favicon.svg');

    $this->get($path)
        ->assertOk()
        ->assertSee('aria-label="Aether home"', false)
        ->assertSee('<span class="brand__wordmark">AETHER</span>', false)
        ->assertSee('class="brand__mark" src="'.$brandAssetUrl.'" alt=""', false)
        ->assertSee('<link rel="icon" type="image/svg+xml" href="'.$brandAssetUrl.'">', false);
})->with(['header' => '/', 'authentication card' => '/login']);

it('shows a signed-in welcome page without guest registration or login links', function (bool $verified): void {
    $user = User::factory()->create(['email_verified_at' => $verified ? now() : null]);

    $this->actingAs($user)->get('/')
        ->assertOk()
        ->assertSee('Welcome back.')
        ->assertSee('Open your account')
        ->assertSee('href="'.route('account.profile').'"', false)
        ->assertSee('Sign out')
        ->assertDontSee('One identity, every application.')
        ->assertDontSee('Create an account')
        ->assertDontSee('Already registered?')
        ->assertDontSee('href="'.route('register').'"', false)
        ->assertDontSee('href="'.route('login').'"', false);
})->with(['verified' => true, 'unverified' => false]);

it('restores the guest welcome page after signing out', function (): void {
    $this->actingAs(User::factory()->create())->post('/logout')->assertRedirect();

    $this->assertGuest();
    $this->get('/')
        ->assertOk()
        ->assertSee('Create an account')
        ->assertSee('href="'.route('login').'"', false)
        ->assertDontSee('Welcome back.')
        ->assertDontSee('Open your account');
});

it('exposes the application health endpoint', function (): void {
    $this->get('/up')->assertOk();
});

it('does not expose exception details in an unknown API response', function (): void {
    $this->getJson('/api/unknown')
        ->assertNotFound()
        ->assertJsonMissingPath('exception')
        ->assertJsonMissingPath('trace');
});

it('creates the foundation schema in an isolated test database', function (): void {
    expect(Schema::hasTable('users'))->toBeTrue()
        ->and(Schema::hasTable('sessions'))->toBeTrue()
        ->and(Schema::hasTable('jobs'))->toBeTrue()
        ->and(Schema::hasTable('cache'))->toBeTrue();

    $user = User::factory()->create();

    $this->assertDatabaseHas('users', ['id' => $user->id, 'email' => $user->email]);
});
