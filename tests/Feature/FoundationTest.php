<?php

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Schema;
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
        ->assertDontSee('tailwind');
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
