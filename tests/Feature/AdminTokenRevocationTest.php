<?php

use App\Actions\Admin\RevokeApplicationTokens;
use App\Enums\OAuthAppType;
use App\Enums\OAuthAuditEvent;
use App\Enums\OAuthClientStatus;
use App\Models\AuditLog;
use App\Models\Consent;
use App\Models\User;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;

uses(RefreshDatabase::class);

function tokenRevocationAdministrator(): User
{
    return User::factory()->create([
        'is_admin' => true, 'two_factor_secret' => Crypt::encryptString('test-only-admin-secret'),
        'two_factor_confirmed_at' => now(),
    ]);
}

it('requires verified confirmed two factor administrators recent password and explicit confirmation', function (): void {
    $client = oauthClientFixture(User::factory()->create(), true);
    $url = route('admin.apps.tokens.revoke', $client);
    $this->get($url)->assertRedirect('/login');
    $this->post($url, ['confirm' => true])->assertRedirect('/login');
    $this->actingAs(User::factory()->create(['is_developer' => true]))->get($url)->assertForbidden();
    $this->post($url, ['confirm' => true])->assertForbidden();
    $admin = tokenRevocationAdministrator();
    $admin->forceFill(['email_verified_at' => null])->save();
    $this->actingAs($admin)->get($url)->assertRedirect('/email/verify');
    $admin->forceFill(['email_verified_at' => now(), 'two_factor_confirmed_at' => null])->save();
    $this->actingAs($admin)->post($url, ['confirm' => true])->assertRedirect(route('account.security'));
    $admin->forceFill(['two_factor_confirmed_at' => now()])->save();
    $this->actingAs($admin)->get($url)->assertRedirect(route('password.confirm'));
    $this->withSession(['auth.password_confirmed_at' => now()->subSeconds(301)->timestamp])
        ->post($url, ['confirm' => true])->assertRedirect(route('password.confirm'));
    $this->withSession(['auth.password_confirmed_at' => now()->timestamp])
        ->post($url)->assertRedirect(route('admin.apps.tokens.revoke.confirm', $client))->assertSessionHasErrors('confirm');
    expect(AuditLog::count())->toBe(0);
});

it('revokes existing Web credentials and pending codes while preserving Live state consent and new issuance', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner, true);
    $other = oauthClientFixture($owner, true);
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, $owner, $client)))->assertOk()->json();
    $otherTokens = $this->postJson('/oauth/token', oauthExchange($other, oauthCode($this, $owner, $other)))->assertOk()->json();
    $pending = oauthCode($this, $owner, $client);
    $before = $client->fresh()->getAttributes();
    $consents = Consent::query()->get()->toArray();
    $admin = tokenRevocationAdministrator();

    $this->actingAs($admin)->withSession(['auth.password_confirmed_at' => now()->timestamp])
        ->get(route('admin.apps.tokens.revoke.confirm', $client))->assertOk()
        ->assertHeader('Cache-Control', 'no-store, private')->assertSee('Existing sessions inside the client app may remain signed in.')
        ->assertDontSee($client->plainSecret)->assertDontSee($client->secret);
    $this->post(route('admin.apps.tokens.revoke', $client), ['confirm' => true, 'status' => 'suspended', 'allowed_scopes' => []])
        ->assertRedirect(route('admin.apps.show', $client))->assertHeader('Cache-Control', 'no-store, private');
    expect($client->fresh()->getAttributes())->toBe($before)
        ->and(Consent::query()->get()->toArray())->toBe($consents)
        ->and(oauthBearerWorks($tokens['access_token']))->toBeFalse()
        ->and(oauthBearerWorks($otherTokens['access_token']))->toBeTrue();
    $this->postJson('/oauth/token', ['grant_type' => 'refresh_token', 'client_id' => $client->id,
        'client_secret' => $client->plainSecret, 'refresh_token' => $tokens['refresh_token']])->assertStatus(400);
    $this->postJson('/oauth/token', oauthExchange($client, $pending))->assertStatus(400);
    $newCode = oauthCode($this, $owner, $client);
    $replacement = $this->postJson('/oauth/token', oauthExchange($client, $newCode))->assertOk();
    expect(oauthBearerWorks($replacement->json('access_token')))->toBeTrue();
    $audit = AuditLog::where('event', OAuthAuditEvent::ClientTokensRevoked)->sole();
    expect($audit->user_id)->toBe($admin->id)->and($audit->client_id)->toBe($client->id);
    $this->actingAs($admin)->get(route('admin.audit.index', ['event' => 'client.tokens_revoked']))
        ->assertOk()->assertSee('client.tokens_revoked');
});

it('preserves public client type and availability when revoking tokens', function (OAuthAppType $type, OAuthClientStatus $status): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner);
    $client->forceFill(['app_type' => $type, 'status' => $status])->save();
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, $owner, $client)))->assertOk()->json();
    $this->actingAs(tokenRevocationAdministrator())->withSession(['auth.password_confirmed_at' => now()->timestamp])
        ->post(route('admin.apps.tokens.revoke', $client), ['confirm' => true])->assertRedirect();
    expect($client->fresh()->status)->toBe($status)->and($client->fresh()->app_type)->toBe($type)
        ->and($client->fresh()->confidential())->toBeFalse()->and(oauthBearerWorks($tokens['access_token']))->toBeFalse();
})->with([
    [OAuthAppType::Spa, OAuthClientStatus::Testing], [OAuthAppType::Spa, OAuthClientStatus::Live],
    [OAuthAppType::Mobile, OAuthClientStatus::Testing], [OAuthAppType::Mobile, OAuthClientStatus::Live],
]);

it('revokes Machine credentials across batches without changing permissions or blocking new issuance', function (): void {
    $client = app(ClientRepository::class)->createClientCredentialsGrantClient('Machine fixture');
    $client->forceFill(['status' => OAuthClientStatus::Live, 'app_type' => OAuthAppType::Machine, 'allowed_scopes' => ['stats:read']])->save();
    $request = ['grant_type' => 'client_credentials', 'client_id' => $client->id, 'client_secret' => $client->plainSecret, 'scope' => 'stats:read'];
    $this->postJson('/oauth/token', $request)->assertOk();
    $tokens = [];
    $refreshTokens = [];
    for ($number = 0; $number < 501; $number++) {
        $identifier = str_pad((string) $number, 80, '0', STR_PAD_LEFT);
        $tokens[] = ['id' => $identifier, 'client_id' => $client->id, 'scopes' => '[]', 'revoked' => false, 'expires_at' => now()->addHour()];
        $refreshTokens[] = ['id' => $identifier, 'access_token_id' => $identifier, 'revoked' => false, 'expires_at' => now()->addDay()];
    }
    DB::table('oauth_access_tokens')->insert($tokens);
    DB::table('oauth_refresh_tokens')->insert($refreshTokens);
    $before = $client->fresh()->getAttributes();
    $this->actingAs(tokenRevocationAdministrator())->withSession(['auth.password_confirmed_at' => now()->timestamp])
        ->post(route('admin.apps.tokens.revoke', $client), ['confirm' => true])->assertRedirect();
    expect($client->fresh()->getAttributes())->toBe($before)
        ->and(Passport::token()->newQuery()->where('revoked', false)->count())->toBe(0)
        ->and(Passport::refreshToken()->newQuery()->where('revoked', false)->count())->toBe(0);
    $this->postJson('/oauth/token', $request)->assertOk();
});

it('hides and refuses revocation for Suspended or permanently revoked clients', function (bool $revoked): void {
    $client = oauthClientFixture(User::factory()->create(), true);
    $client->forceFill(['status' => OAuthClientStatus::Suspended, 'revoked' => $revoked])->save();
    $this->actingAs(tokenRevocationAdministrator())->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    $this->get(route('admin.apps.show', $client))->assertOk()->assertDontSee('Revoke tokens');
    $this->get(route('admin.apps.tokens.revoke.confirm', $client))->assertForbidden();
    $this->post(route('admin.apps.tokens.revoke', $client), ['confirm' => true])->assertForbidden();
    expect(AuditLog::count())->toBe(0);
})->with([false, true]);

it('rechecks current policy under the client lock', function (): void {
    $client = oauthClientFixture(User::factory()->create(), true);
    $this->actingAs(tokenRevocationAdministrator());
    $client->newQuery()->whereKey($client->id)->update(['revoked' => true]);
    expect(fn () => app(RevokeApplicationTokens::class)->handle($client))->toThrow(AuthorizationException::class);
    expect(AuditLog::count())->toBe(0);
});

it('rolls back credential revocation if auditing fails', function (): void {
    $owner = User::factory()->create();
    $client = oauthClientFixture($owner, true);
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, $owner, $client)))->assertOk()->json();
    $this->actingAs(tokenRevocationAdministrator());
    AuditLog::creating(function (AuditLog $audit): void {
        if ($audit->event === OAuthAuditEvent::ClientTokensRevoked) {
            throw new RuntimeException('Test audit failure');
        }
    });
    try {
        expect(fn () => app(RevokeApplicationTokens::class)->handle($client))->toThrow(RuntimeException::class);
        expect(oauthBearerWorks($tokens['access_token']))->toBeTrue()
            ->and(AuditLog::where('event', OAuthAuditEvent::ClientTokensRevoked)->count())->toBe(0);
    } finally {
        AuditLog::flushEventListeners();
    }
});
