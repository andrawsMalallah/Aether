<?php

use App\Actions\Account\DisconnectApp;
use App\Actions\Account\ListConnectedApps;
use App\Enums\OAuthAuditEvent;
use App\Enums\OAuthClientStatus;
use App\Models\AuditLog;
use App\Models\Consent;
use App\Models\OAuthClient;
use App\Models\User;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\Passport;

uses(RefreshDatabase::class);

function connectedAppConsent(User $user, OAuthClient $client, array $overrides = []): Consent
{
    return Consent::create(array_replace([
        'user_id' => $user->id, 'client_id' => $client->id, 'scopes' => ['openid', 'email'],
        'granted_at' => now(), 'revoked_at' => null,
    ], $overrides));
}

it('paginates only owned active saved approvals without credentials and escapes app names', function (): void {
    $user = User::factory()->create();
    $client = oauthClientFixture(null, true);
    $client->forceFill(['name' => '<script>untrusted</script>'])->save();
    connectedAppConsent($user, $client);
    $foreignClient = oauthClientFixture();
    $foreignClient->forceFill(['name' => 'Foreign approval'])->save();
    connectedAppConsent(User::factory()->create(), $foreignClient);
    $revokedClient = oauthClientFixture();
    $revokedClient->forceFill(['name' => 'Withdrawn approval'])->save();
    connectedAppConsent($user, $revokedClient, ['revoked_at' => now()]);
    $this->actingAs($user)->withSession(['auth.password_confirmed_at' => now()->timestamp])
        ->get(route('account.connected-apps.index'))->assertOk()->assertHeader('Cache-Control', 'no-store, private')
        ->assertSee('<script>untrusted</script>')->assertDontSee('<script>untrusted</script>', false)
        ->assertSee('See your email address')->assertSee('UTC')->assertDontSee('Foreign approval')->assertDontSee('Withdrawn approval')
        ->assertDontSee($client->plainSecret)->assertDontSee($client->secret);
    foreach (range(1, 12) as $number) {
        connectedAppConsent($user, oauthClientFixture());
    }
    $this->get(route('account.connected-apps.index'))->assertOk()->assertSee('Page 1 of 2');
    $this->get(route('account.connected-apps.index', ['page' => ['bad']]))
        ->assertRedirect(route('account.connected-apps.index'))->assertSessionHasErrors('page');
    $this->actingAs(User::factory()->create());
    expect(fn () => app(ListConnectedApps::class)->handle($user))->toThrow(AuthorizationException::class);
});

it('requires verified own-account access recent password and explicit disconnection confirmation', function (): void {
    $user = User::factory()->create();
    $consent = connectedAppConsent($user, oauthClientFixture());
    $url = route('account.connected-apps.disconnect', $consent);
    $this->get(route('account.connected-apps.index'))->assertRedirect('/login');
    $this->post($url, ['confirm' => true])->assertRedirect('/login');
    $this->actingAs(User::factory()->unverified()->create())->post($url, ['confirm' => true])->assertRedirect('/email/verify');
    $this->actingAs($user)->withSession(['auth.password_confirmed_at' => now()->subSeconds(301)->timestamp])
        ->post($url, ['confirm' => true])->assertRedirect(route('password.confirm'));
    $this->withSession(['auth.password_confirmed_at' => now()->timestamp])->post($url)->assertSessionHasErrors('confirm');
    $this->actingAs(User::factory()->create())->post($url, ['confirm' => true])->assertForbidden();
    expect($consent->fresh()->revoked_at)->toBeNull()->and(AuditLog::count())->toBe(0);
});

it('disconnects only the users app credentials while keeping other users and apps working', function (): void {
    $user = User::factory()->create();
    $otherUser = User::factory()->create();
    $client = oauthClientFixture(null, true);
    $otherClient = oauthClientFixture(null, true);
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, $user, $client)))->assertOk()->json();
    $otherUserTokens = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, $otherUser, $client)))->assertOk()->json();
    $otherAppTokens = $this->postJson('/oauth/token', oauthExchange($otherClient, oauthCode($this, $user, $otherClient)))->assertOk()->json();
    $pending = oauthCode($this, $user, $client);
    $consent = Consent::where('user_id', $user->id)->where('client_id', $client->id)->sole();
    $clientBefore = $client->fresh()->getAttributes();
    $rememberBefore = $user->remember_token;
    $this->actingAs($user)->withSession(['auth.password_confirmed_at' => now()->timestamp])
        ->post(route('account.connected-apps.disconnect', $consent), ['confirm' => true])
        ->assertRedirect(route('account.connected-apps.index'))->assertHeader('Cache-Control', 'no-store, private');
    $this->assertAuthenticatedAs($user);
    expect($consent->fresh()->revoked_at)->not->toBeNull()
        ->and($client->fresh()->getAttributes())->toBe($clientBefore)
        ->and($user->fresh()->remember_token)->toBe($rememberBefore)
        ->and(oauthBearerWorks($tokens['access_token']))->toBeFalse()
        ->and(oauthBearerWorks($otherUserTokens['access_token']))->toBeTrue()
        ->and(oauthBearerWorks($otherAppTokens['access_token']))->toBeTrue();
    $this->postJson('/oauth/token', ['grant_type' => 'refresh_token', 'client_id' => $client->id,
        'client_secret' => $client->plainSecret, 'refresh_token' => $tokens['refresh_token']])->assertStatus(400);
    $this->postJson('/oauth/token', oauthExchange($client, $pending))->assertStatus(400);
    $this->actingAs($user)->get(oauthAuthorizeUrl(oauthParameters($client)))->assertOk()->assertSee('Allow');
    $replacementCode = oauthCode($this, $user, $client);
    $this->postJson('/oauth/token', oauthExchange($client, $replacementCode))->assertOk();
    expect($consent->fresh()->revoked_at)->toBeNull();
    $audit = AuditLog::where('event', OAuthAuditEvent::ConsentRevoked)->sole();
    expect($audit->user_id)->toBe($user->id)->and($audit->client_id)->toBe($client->id);
});

it('permits withdrawal from unavailable retained apps and hides already withdrawn approvals', function (bool $revoked): void {
    $user = User::factory()->create();
    $client = oauthClientFixture();
    $client->forceFill(['status' => OAuthClientStatus::Suspended, 'revoked' => $revoked])->save();
    $consent = connectedAppConsent($user, $client);
    $this->actingAs($user)->withSession(['auth.password_confirmed_at' => now()->timestamp])
        ->get(route('account.connected-apps.index'))->assertOk()->assertSee('This application is unavailable.');
    $this->post(route('account.connected-apps.disconnect', $consent), ['confirm' => true])->assertRedirect();
    $this->get(route('account.connected-apps.index'))->assertOk()->assertSee('No applications have your saved approval.');
    $this->post(route('account.connected-apps.disconnect', $consent), ['confirm' => true])->assertForbidden();
})->with([false, true]);

it('revokes user credentials beyond the chunk boundary and preserves another users rows', function (): void {
    $user = User::factory()->create();
    $other = User::factory()->create();
    $client = oauthClientFixture();
    $consent = connectedAppConsent($user, $client);
    $tokens = [];
    $refreshTokens = [];
    foreach (range(0, 501) as $number) {
        $identifier = str_pad((string) $number, 80, '0', STR_PAD_LEFT);
        $tokens[] = ['id' => $identifier, 'user_id' => $number === 501 ? $other->id : $user->id,
            'client_id' => $client->id, 'scopes' => '[]', 'revoked' => false, 'expires_at' => now()->addHour()];
        $refreshTokens[] = ['id' => $identifier, 'access_token_id' => $identifier, 'revoked' => false, 'expires_at' => now()->addDay()];
    }
    DB::table('oauth_access_tokens')->insert($tokens);
    DB::table('oauth_refresh_tokens')->insert($refreshTokens);
    $this->actingAs($user);
    app(DisconnectApp::class)->handle($user, $consent);
    expect(Passport::token()->newQuery()->where('revoked', false)->count())->toBe(1)
        ->and(Passport::refreshToken()->newQuery()->where('revoked', false)->count())->toBe(1);
});

it('rechecks locked consent state and rolls back credential and consent changes when auditing fails', function (): void {
    $user = User::factory()->create();
    $client = oauthClientFixture();
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, $user, $client)))->assertOk()->json();
    $consent = Consent::where('user_id', $user->id)->where('client_id', $client->id)->sole();
    AuditLog::creating(function (AuditLog $audit): void {
        if ($audit->event === OAuthAuditEvent::ConsentRevoked) {
            throw new RuntimeException('Synthetic audit failure');
        }
    });
    try {
        expect(fn () => app(DisconnectApp::class)->handle($user, $consent))->toThrow(RuntimeException::class);
        expect($consent->fresh()->revoked_at)->toBeNull()->and(oauthBearerWorks($tokens['access_token']))->toBeTrue();
    } finally {
        AuditLog::flushEventListeners();
    }
    Consent::whereKey($consent->id)->update(['revoked_at' => now()]);
    expect(fn () => app(DisconnectApp::class)->handle($user, $consent))->toThrow(AuthorizationException::class);
});

it('holds a transaction during automatic authorization code issuance from saved consent', function (): void {
    $user = User::factory()->create();
    $client = oauthClientFixture();
    oauthCode($this, $user, $client);
    $codeClass = Passport::authCode()::class;
    $observed = false;
    $codeClass::creating(function () use (&$observed): void {
        $observed = true;
        expect(DB::transactionLevel())->toBeGreaterThan(1); // RefreshDatabase owns the outer test transaction.
    });
    try {
        $this->actingAs($user)->get(oauthAuthorizeUrl(oauthParameters($client)))->assertRedirect();
        expect($observed)->toBeTrue();
    } finally {
        $codeClass::flushEventListeners();
    }
});
