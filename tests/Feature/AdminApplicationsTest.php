<?php

use App\Actions\Admin\RestoreApplication;
use App\Actions\Admin\SuspendApplication;
use App\Enums\OAuthAppType;
use App\Enums\OAuthAuditEvent;
use App\Enums\OAuthClientStatus;
use App\Models\AuditLog;
use App\Models\User;
use App\Services\OAuth\RevokeClientCredentials;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;

uses(RefreshDatabase::class);

it('combines application name or exact id search with status and type and distinguishes revoked clients', function (): void {
    $owner = User::factory()->create();
    $live = oauthClientFixture($owner, true);
    $live->forceFill(['name' => 'Matching web'])->save();
    $revoked = oauthClientFixture($owner, true);
    $revoked->forceFill(['name' => 'Matching revoked', 'revoked' => true])->save();
    $spa = oauthClientFixture($owner);
    $spa->forceFill(['name' => 'Matching SPA'])->save();
    $suspended = oauthClientFixture($owner, true);
    $suspended->forceFill(['name' => 'Matching suspended', 'status' => OAuthClientStatus::Suspended])->save();
    $this->actingAs(administratorFixture());
    foreach ([
        ['search' => 'matching', 'status' => 'live', 'type' => 'web', 'expected' => $live->id],
        ['search' => $spa->id, 'type' => 'spa', 'expected' => $spa->id],
        ['status' => 'revoked', 'expected' => $revoked->id],
        ['search' => 'Matching', 'status' => 'suspended', 'type' => 'web', 'expected' => $suspended->id],
    ] as $case) {
        $expected = $case['expected'];
        unset($case['expected']);
        $this->get('/admin/apps?'.http_build_query($case))->assertOk()
            ->assertViewHas('applications', fn ($applications): bool => $applications->total() === 1 && $applications->first()['id'] === $expected)
            ->assertHeader('Cache-Control', 'no-store, private');
    }
    $this->get('/admin/apps?search='.$spa->id.'&type=web')->assertOk()->assertSee('No applications match your filters.');
});

it('treats search wildcard characters and injection as literal data and escapes reflected text', function (): void {
    $client = oauthClientFixture(User::factory()->create(), true);
    $client->forceFill(['name' => 'Literal 100%_! marker'])->save();
    oauthClientFixture(User::factory()->create(), true);
    $this->actingAs(administratorFixture())->get('/admin/apps?'.http_build_query(['search' => '%_!']))->assertOk()
        ->assertViewHas('applications', fn ($applications): bool => $applications->total() === 1);
    $this->get('/admin/apps?'.http_build_query(['search' => "' OR 1=1 --"]))->assertOk()
        ->assertSee('No applications match your filters.');
    $this->get('/admin/apps?'.http_build_query(['search' => '<script>alert(1)</script>']))->assertOk()
        ->assertSee('&lt;script&gt;alert(1)&lt;/script&gt;', false)->assertDontSee('<script>alert(1)</script>', false);
});

it('preserves only validated filters across pages and applying filters resets the page', function (): void {
    $owner = User::factory()->create();
    for ($number = 0; $number < 13; $number++) {
        $client = oauthClientFixture($owner, true);
        $client->forceFill(['name' => 'Page fixture '.$number])->save();
    }
    $this->actingAs(administratorFixture())->get('/admin/apps?search=Page&status=live&type=web&unrelated=discard')->assertOk()
        ->assertViewHas('applications', function ($applications): bool {
            parse_str(parse_url($applications->nextPageUrl(), PHP_URL_QUERY), $query);

            return $applications->total() === 13 && $applications->count() === 12 && $query === ['search' => 'Page', 'status' => 'live', 'type' => 'web', 'page' => '2'];
        });
    $this->get('/admin/apps?search=Page&status=live&type=web&page=2')->assertOk()
        ->assertViewHas('applications', fn ($applications): bool => $applications->count() === 1)
        ->assertDontSee('name="page"', false)->assertSee('value="live" selected', false);
    $this->get('/admin/apps')->assertOk()->assertViewHas('filters', []);
});

it('rejects malformed application filters without flashing array input or redirect loops', function (array $filters, string $field): void {
    $this->actingAs(administratorFixture())->get('/admin/apps?'.http_build_query($filters))
        ->assertRedirect(route('admin.apps.index'))->assertSessionHasErrors($field);
    $this->get('/admin/apps')->assertOk()->assertSee('Search applications');
})->with([
    'search array' => [['search' => ['bad']], 'search'],
    'long search' => [['search' => str_repeat('x', 256)], 'search'],
    'status array' => [['status' => ['live']], 'status'],
    'unknown status' => [['status' => 'unknown'], 'status'],
    'type array' => [['type' => ['web']], 'type'],
    'unknown type' => [['type' => 'desktop'], 'type'],
    'page array' => [['page' => [2]], 'page'],
    'negative page' => [['page' => -1], 'page'],
]);

it('warns about ownerless restoration and never silently assigns ownership or enables sign in', function (): void {
    $client = oauthClientFixture(confidential: true);
    $client->forceFill(['status' => OAuthClientStatus::Suspended])->save();
    $admin = administratorFixture();
    $this->actingAs($admin)->withSession(['auth.password_confirmed_at' => now()->timestamp])
        ->get(route('admin.apps.show', $client))->assertOk()->assertSee('No owner is assigned.');
    $this->get(route('admin.apps.restore.confirm', $client))->assertOk()->assertSee('nobody can sign in');
    $this->post(route('admin.apps.restore', $client), ['confirm' => true])->assertRedirect();
    expect($client->fresh()->owner_id)->toBeNull()->and($client->fresh()->status)->toBe(OAuthClientStatus::Testing)
        ->and($client->fresh()->acceptsUser($admin))->toBeFalse();
});

it('restores to owner only testing without reviving credentials and allows explicit owner publication', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner, true);
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, $owner, $client)))->assertOk()->json();
    $pending = oauthCode($this, $owner, $client);
    $admin = administratorFixture();
    $this->actingAs($admin)->withSession(['auth.password_confirmed_at' => now()->timestamp])
        ->post(route('admin.apps.suspend', $client), ['confirm' => true])->assertRedirect();
    $original = $client->fresh()->getRawOriginal();
    $this->get(route('admin.apps.restore.confirm', $client))->assertOk()->assertSee('Previous tokens and pending sign-ins will remain invalid.');
    $this->post(route('admin.apps.restore', $client), ['confirm' => true, 'status' => 'live', 'revoked' => false, 'secret' => 'injected'])
        ->assertRedirect(route('admin.apps.show', $client))->assertHeader('Cache-Control', 'no-store, private');
    $restored = $client->fresh();
    expect($restored->status)->toBe(OAuthClientStatus::Testing)->and($restored->secret)->toBe($original['secret'])
        ->and($restored->owner_id)->toBe($owner->id)->and($restored->grant_types)->toBe($client->grant_types)
        ->and(oauthBearerWorks($tokens['access_token']))->toBeFalse();
    $audit = AuditLog::where('event', OAuthAuditEvent::ClientRestored)->sole();
    expect($audit->user_id)->toBe($admin->id)->and($audit->client_id)->toBe($client->id);
    $this->post(route('admin.apps.restore', $client), ['confirm' => true])->assertForbidden();
    $this->actingAs(User::factory()->create())->get(oauthAuthorizeUrl(oauthParameters($client)))->assertForbidden();
    $freshCode = oauthCode($this, $owner, $client);
    $this->postJson('/oauth/token', oauthExchange($client, $freshCode))->assertOk();
    $this->actingAs($owner)->withSession(['auth.password_confirmed_at' => now()->timestamp])
        ->post(route('developer.apps.publish.store', $client), ['confirm' => true])->assertRedirect();
    expect($client->fresh()->status)->toBe(OAuthClientStatus::Live);
    $this->postJson('/oauth/token', oauthExchange($client, $pending))->assertStatus(400);
    $this->postJson('/oauth/token', ['grant_type' => 'refresh_token', 'client_id' => $client->id, 'client_secret' => $client->plainSecret, 'refresh_token' => $tokens['refresh_token']])->assertStatus(400);
    expect(oauthBearerWorks($tokens['access_token']))->toBeFalse();
});

it('protects restoration with verified admin two factor recent password and explicit confirmation', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner, true);
    $client->forceFill(['status' => OAuthClientStatus::Suspended])->save();
    $url = route('admin.apps.restore', $client);
    $this->get($url)->assertRedirect('/login');
    $this->post($url, ['confirm' => true])->assertRedirect('/login');
    $this->actingAs($owner)->get($url)->assertForbidden();
    $this->post($url, ['confirm' => true])->assertForbidden();
    $admin = administratorFixture();
    $admin->forceFill(['email_verified_at' => null])->save();
    $this->actingAs($admin)->post($url, ['confirm' => true])->assertRedirect('/email/verify');
    $admin->forceFill(['email_verified_at' => now(), 'two_factor_confirmed_at' => null])->save();
    $this->actingAs($admin)->post($url, ['confirm' => true])->assertRedirect(route('account.security'));
    $admin->forceFill(['two_factor_confirmed_at' => now()])->save();
    $this->actingAs($admin)->get($url)->assertRedirect(route('password.confirm'));
    $this->post($url, ['confirm' => true])->assertRedirect(route('password.confirm'));
    $this->withSession(['auth.password_confirmed_at' => now()->subSeconds(301)->timestamp])->post($url, ['confirm' => true])->assertRedirect(route('password.confirm'));
    $this->withSession(['auth.password_confirmed_at' => now()->timestamp])->post($url)->assertSessionHasErrors('confirm');
    expect($client->fresh()->status)->toBe(OAuthClientStatus::Suspended);
});

it('refuses restoration of available or revoked applications', function (string $state): void {
    $client = oauthClientFixture(User::factory()->create(), true);
    $client->forceFill(['status' => $state === 'revoked' ? OAuthClientStatus::Suspended : OAuthClientStatus::from($state), 'revoked' => $state === 'revoked'])->save();
    $this->actingAs(administratorFixture())->withSession(['auth.password_confirmed_at' => now()->timestamp])
        ->get(route('admin.apps.restore.confirm', $client))->assertForbidden();
    $this->post(route('admin.apps.restore', $client), ['confirm' => true])->assertForbidden();
    expect(AuditLog::count())->toBe(0);
})->with(['live', 'testing', 'revoked']);

it('rechecks locked restoration state and rolls back if credential cleanup fails', function (): void {
    $client = oauthClientFixture(User::factory()->create(), true);
    $client->forceFill(['status' => OAuthClientStatus::Suspended])->save();
    $this->actingAs(administratorFixture());
    $client->newQuery()->whereKey($client->id)->update(['revoked' => true]);
    expect(fn () => app(RestoreApplication::class)->handle($client))->toThrow(AuthorizationException::class);
    $client->newQuery()->whereKey($client->id)->update(['revoked' => false]);
    $this->mock(RevokeClientCredentials::class)->shouldReceive('handle')->once()->andThrow(new RuntimeException('Test cleanup failure'));
    expect(fn () => app(RestoreApplication::class)->handle($client))->toThrow(RuntimeException::class);
    expect($client->fresh()->status)->toBe(OAuthClientStatus::Suspended)->and(AuditLog::count())->toBe(0);
});

it('suspends machine clients and revokes credentials beyond one batch without affecting other clients', function (): void {
    $machine = app(ClientRepository::class)->createClientCredentialsGrantClient('Machine fixture');
    $machine->forceFill(['status' => OAuthClientStatus::Live, 'app_type' => OAuthAppType::Machine, 'allowed_scopes' => ['stats:read']])->save();
    $request = ['client_id' => $machine->id, 'client_secret' => $machine->plainSecret, 'grant_type' => 'client_credentials', 'scope' => 'stats:read'];
    $this->postJson('/oauth/token', $request)->assertOk();
    $tokens = [];
    $refreshTokens = [];
    for ($number = 0; $number < 501; $number++) {
        $identifier = str_pad((string) $number, 80, '0', STR_PAD_LEFT);
        $tokens[] = ['id' => $identifier, 'client_id' => $machine->id, 'scopes' => '[]', 'revoked' => false, 'expires_at' => now()->addHour()];
        $refreshTokens[] = ['id' => $identifier, 'access_token_id' => $identifier, 'revoked' => false, 'expires_at' => now()->addDay()];
    }
    DB::table('oauth_access_tokens')->insert($tokens);
    DB::table('oauth_refresh_tokens')->insert($refreshTokens);
    $this->actingAs(administratorFixture())->withSession(['auth.password_confirmed_at' => now()->timestamp])
        ->post('/admin/apps/'.$machine->id.'/suspend', ['confirm' => true])->assertRedirect();
    expect(Passport::token()->newQuery()->where('client_id', $machine->id)->where('revoked', false)->count())->toBe(0)
        ->and(Passport::refreshToken()->newQuery()->where('revoked', false)->count())->toBe(0);
    $this->postJson('/oauth/token', $request)->assertStatus(401);
});

it('rolls back status revocations and audit if suspension cleanup fails', function (): void {
    $client = oauthClientFixture(User::factory()->create(), true);
    $this->actingAs(administratorFixture());
    $this->mock(RevokeClientCredentials::class)->shouldReceive('handle')->once()->andThrow(new RuntimeException('Test cleanup failure'));
    expect(fn () => app(SuspendApplication::class)->handle($client))->toThrow(RuntimeException::class);
    expect($client->fresh()->status)->toBe(OAuthClientStatus::Live)->and(AuditLog::count())->toBe(0);
});

function administratorFixture(): User
{
    return User::factory()->create([
        'is_admin' => true, 'two_factor_secret' => Crypt::encryptString('test-only-totp-secret'),
        'two_factor_confirmed_at' => now(),
    ]);
}

it('requires verified admin access and confirmed two factor authentication on every admin route', function (): void {
    $client = oauthClientFixture(User::factory()->create(), true);
    $paths = ['/admin/apps', '/admin/apps/'.$client->id, '/admin/apps/'.$client->id.'/suspend'];
    foreach ($paths as $path) {
        $this->get($path)->assertRedirect('/login');
    }
    $this->actingAs(User::factory()->create(['is_developer' => true]));
    foreach ($paths as $path) {
        $this->get($path)->assertForbidden();
    }
    $this->post('/admin/apps/'.$client->id.'/suspend', ['confirm' => true])->assertForbidden();
    $admin = administratorFixture();
    $admin->forceFill(['email_verified_at' => null])->save();
    $this->actingAs($admin)->get('/admin/apps')->assertRedirect('/email/verify');
    $admin->forceFill(['email_verified_at' => now(), 'two_factor_confirmed_at' => null])->save();
    $this->actingAs($admin);
    foreach ($paths as $path) {
        $this->get($path)->assertRedirect(route('account.security'));
    }
    $this->post('/admin/apps/'.$client->id.'/suspend', ['confirm' => true])->assertRedirect(route('account.security'));
    expect($client->fresh()->status)->toBe(OAuthClientStatus::Live);
});

it('paginates all owners applications and renders safe admin details without consuming secrets', function (): void {
    $admin = administratorFixture();
    $client = oauthClientFixture(User::factory()->create(), true);
    $client->forceFill(['name' => '<script>unsafe</script>'])->save();
    for ($number = 0; $number < 12; $number++) {
        oauthClientFixture(User::factory()->create(), true);
    }
    $encrypted = Crypt::encryptString($client->plainSecret);
    $this->actingAs($admin)->withSession(['developer.credentials.'.$client->id => $encrypted])
        ->get('/admin/apps')->assertOk()->assertHeader('Cache-Control', 'no-store, private')
        ->assertViewHas('applications', fn ($applications): bool => $applications->count() === 12 && $applications->total() === 13);
    $this->get('/admin/apps?page=2')->assertOk()->assertViewHas('applications', fn ($applications): bool => $applications->count() === 1);
    $this->get('/admin/apps/'.$client->id)->assertOk()->assertSee('&lt;script&gt;unsafe&lt;/script&gt;', false)
        ->assertDontSee('<script>unsafe</script>', false)->assertSee('Suspend application')
        ->assertDontSee($client->secret)->assertDontSee($client->plainSecret)
        ->assertHeader('Cache-Control', 'no-store, private');
    expect(session('developer.credentials.'.$client->id))->toBe($encrypted);
    $this->get('/admin/apps/missing')->assertNotFound();
});

it('requires recent password and explicit confirmation before suspension', function (): void {
    $client = oauthClientFixture(User::factory()->create(), true);
    $this->actingAs(administratorFixture())->get('/admin/apps/'.$client->id.'/suspend')->assertRedirect(route('password.confirm'));
    $this->post('/admin/apps/'.$client->id.'/suspend', ['confirm' => true])->assertRedirect(route('password.confirm'));
    $this->withSession(['auth.password_confirmed_at' => now()->subSeconds(301)->timestamp])
        ->post('/admin/apps/'.$client->id.'/suspend', ['confirm' => true])->assertRedirect(route('password.confirm'));
    $this->withSession(['auth.password_confirmed_at' => now()->timestamp])
        ->get('/admin/apps/'.$client->id.'/suspend')->assertOk()->assertSee('Restoring later returns the application to Testing.');
    $this->post('/admin/apps/'.$client->id.'/suspend')->assertSessionHasErrors('confirm');
    expect($client->fresh()->status)->toBe(OAuthClientStatus::Live)->and(AuditLog::count())->toBe(0);
});

it('suspends an app atomically and blocks existing tokens refresh pending codes and new sign ins', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner, true);
    $other = oauthClientFixture($owner, true);
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, $owner, $client)))->assertOk()->json();
    $otherTokens = $this->postJson('/oauth/token', oauthExchange($other, oauthCode($this, $owner, $other)))->assertOk()->json();
    $pending = oauthCode($this, $owner, $client);
    $admin = administratorFixture();
    $originalSecret = $client->secret;
    $this->actingAs($admin)->withSession(['auth.password_confirmed_at' => now()->timestamp])
        ->post('/admin/apps/'.$client->id.'/suspend', ['confirm' => true, 'status' => 'live', 'owner_id' => $admin->id])
        ->assertRedirect(route('admin.apps.show', $client))->assertHeader('Cache-Control', 'no-store, private');
    expect($client->fresh()->status)->toBe(OAuthClientStatus::Suspended)
        ->and($client->fresh()->secret)->toBe($originalSecret)->and($client->fresh()->owner_id)->toBe($owner->id)
        ->and(oauthBearerWorks($tokens['access_token']))->toBeFalse()
        ->and(oauthBearerWorks($otherTokens['access_token']))->toBeTrue()
        ->and(Passport::authCode()->newQuery()->where('client_id', $client->id)->where('revoked', false)->count())->toBe(0)
        ->and(Passport::token()->newQuery()->where('client_id', $client->id)->where('revoked', false)->count())->toBe(0);
    $this->postJson('/oauth/token', ['grant_type' => 'refresh_token', 'client_id' => $client->id, 'client_secret' => $client->plainSecret, 'refresh_token' => $tokens['refresh_token']])->assertStatus(401);
    $this->postJson('/oauth/token', oauthExchange($client, $pending))->assertStatus(401);
    $this->get('/admin/apps/'.$client->id)->assertOk()->assertDontSee('Suspend application')->assertSee('Restore application');
    $this->post('/admin/apps/'.$client->id.'/suspend', ['confirm' => true])->assertForbidden();
    $audit = AuditLog::where('event', OAuthAuditEvent::ClientSuspended)->sole();
    expect($audit->user_id)->toBe($admin->id)->and($audit->client_id)->toBe($client->id);
    $this->actingAs($owner)->get(oauthAuthorizeUrl(oauthParameters($client)))->assertStatus(401);
    $this->get(route('developer.apps.edit', $client))->assertForbidden();
    $this->post(route('developer.apps.publish.store', $client), ['confirm' => true])->assertForbidden();
});

it('rechecks suspension policy on the locked current client and loses access after two factor removal', function (): void {
    $client = oauthClientFixture(User::factory()->create(), true);
    $admin = administratorFixture();
    $this->actingAs($admin);
    $client->newQuery()->whereKey($client->id)->update(['status' => OAuthClientStatus::Suspended]);
    try {
        app(SuspendApplication::class)->handle($client);
        $this->fail('A stale client should not authorize suspension.');
    } catch (AuthorizationException) {
        expect(AuditLog::count())->toBe(0);
    }
    $admin->forceFill(['two_factor_secret' => null, 'two_factor_confirmed_at' => null])->save();
    $this->actingAs($admin)->get('/admin/apps')->assertRedirect(route('account.security'));
});
