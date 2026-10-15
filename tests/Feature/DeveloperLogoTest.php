<?php

use App\Actions\Developer\UpdateApplication;
use App\Enums\OAuthClientStatus;
use App\Models\User;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Storage;

uses(RefreshDatabase::class);

function logoSettings(array $overrides = []): array
{
    return array_replace(['name' => 'Logo app', 'redirect_urls' => 'https://example.com/callback', 'scopes' => ['openid']], $overrides);
}

it('uploads replaces and preserves private generated logos for web and browser apps', function (bool $confidential): void {
    Storage::fake('local');
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner, $confidential);
    $this->actingAs($owner)->get(route('developer.apps.edit', $client))->assertOk()->assertSee('multipart/form-data', false)->assertSee('Upload a logo');
    $this->put(route('developer.apps.update', $client), logoSettings(['logo' => UploadedFile::fake()->image('owner-file.png')]))->assertSessionHasNoErrors();
    $original = $client->fresh()->logo_path;
    expect($original)->toStartWith('oauth-client-logos/')->not->toContain('owner-file');
    Storage::disk('local')->assertExists($original);
    $this->get(route('passport.client.logo', $client))->assertOk()->assertHeader('Cache-Control', 'no-store, private')->assertHeader('X-Content-Type-Options', 'nosniff');
    foreach (['developer.apps.show', 'developer.apps.index'] as $route) {
        $this->get(route($route, $route === 'developer.apps.show' ? $client : []))->assertOk()->assertSee(route('passport.client.logo', $client), false)->assertDontSee($original);
    }
    $this->put(route('developer.apps.update', $client), logoSettings(['logo_path' => 'injected.png']))->assertSessionHasNoErrors();
    expect($client->fresh()->logo_path)->toBe($original);
    $this->put(route('developer.apps.update', $client), logoSettings(['logo' => UploadedFile::fake()->image('replacement.webp')]))->assertSessionHasNoErrors();
    expect($client->fresh()->logo_path)->not->toBe($original);
    Storage::disk('local')->assertExists($original);
})->with([true, false]);

it('rejects active content oversized files and excessive image dimensions', function (): void {
    Storage::fake('local');
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner, true);
    $this->actingAs($owner);
    foreach ([UploadedFile::fake()->create('unsafe.svg', 1, 'image/svg+xml'), UploadedFile::fake()->image('large.png')->size(2049), UploadedFile::fake()->image('wide.png', 4097, 1)] as $file) {
        $this->put(route('developer.apps.update', $client), logoSettings(['logo' => $file]))->assertSessionHasErrors('logo');
    }
    expect($client->fresh()->logo_path)->toBeNull()->and(Storage::disk('local')->allFiles())->toBe([]);
});

it('rejects unauthorized uploads and rechecks lifecycle before storing', function (): void {
    Storage::fake('local');
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner, true);
    $this->actingAs(User::factory()->create(['is_developer' => true]))
        ->put(route('developer.apps.update', $client), logoSettings(['logo' => UploadedFile::fake()->image('logo.png')]))->assertForbidden();
    $this->actingAs($owner);
    $stale = clone $client;
    $client->forceFill(['status' => OAuthClientStatus::Suspended])->save();
    expect(fn () => app(UpdateApplication::class)->handle($stale, ['name' => 'Logo app', 'redirect_uris' => ['https://example.com/callback'], 'scopes' => ['openid'], 'logo' => UploadedFile::fake()->image('logo.png')]))->toThrow(AuthorizationException::class);
    expect(Storage::disk('local')->allFiles())->toBe([]);
});

it('serves suspended and revoked logos only to permitted management users', function (): void {
    Storage::fake('local');
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner, true);
    $client->forceFill(['status' => OAuthClientStatus::Suspended, 'logo_path' => UploadedFile::fake()->image('logo.png')->store('oauth-client-logos', 'local')])->save();
    $url = route('passport.client.logo', $client);
    $this->get($url)->assertRedirect(route('login'));
    $this->actingAs($owner)->get($url)->assertOk();
    $this->actingAs(User::factory()->create())->get($url)->assertForbidden();
    $client->forceFill(['revoked' => true])->save();
    $this->actingAs($owner)->get($url)->assertForbidden();
    $admin = User::factory()->create(['is_admin' => true, 'two_factor_secret' => encrypt('fixture'), 'two_factor_confirmed_at' => now()]);
    $this->actingAs($admin)->get($url)->assertOk();
    $this->get(route('admin.apps.show', $client))->assertOk()->assertSee($url, false);
    $admin->forceFill(['two_factor_confirmed_at' => null])->save();
    $this->get($url)->assertForbidden();
});
