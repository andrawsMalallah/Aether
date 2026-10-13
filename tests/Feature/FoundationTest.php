<?php

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Schema;

uses(RefreshDatabase::class);

it('serves the Aether welcome page with compiled assets', function (): void {
    $this->get('/')
        ->assertOk()
        ->assertSee('AETHER')
        ->assertSee('One identity, every application.')
        ->assertSee('Account registration and sign-in will be available soon.')
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
