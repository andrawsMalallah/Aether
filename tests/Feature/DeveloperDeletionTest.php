<?php

use App\Actions\Developer\DeleteApplication;
use App\Enums\OAuthAppType;
use App\Enums\OAuthAuditEvent;
use App\Enums\OAuthClientStatus;
use App\Models\AuditLog;
use App\Models\User;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\Passport;

uses(RefreshDatabase::class);

it('requires verified developer ownership recent password and explicit confirmation', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner, true);
    $confirmUrl = route('developer.apps.delete.confirm', $client);
    $deleteUrl = route('developer.apps.delete.store', $client);
    $this->get($confirmUrl)->assertRedirect('/login');
    $this->post($deleteUrl, ['confirm' => true])->assertRedirect('/login');
    $this->actingAs($owner)->get($confirmUrl)->assertRedirect(route('password.confirm'));
    $this->post($deleteUrl, ['confirm' => true])->assertRedirect(route('password.confirm'));
    $this->withSession(['auth.password_confirmed_at' => now()->subSeconds(301)->timestamp])
        ->post($deleteUrl, ['confirm' => true])->assertRedirect(route('password.confirm'));
    $this->withSession(['auth.password_confirmed_at' => now()->timestamp])->get($confirmUrl)
        ->assertOk()->assertSee('This cannot be undone.')->assertHeader('Cache-Control', 'no-store, private')
        ->assertDontSee($client->plainSecret)->assertDontSee($client->secret);
    $this->post($deleteUrl)->assertRedirect($confirmUrl)->assertSessionHasErrors('confirm');
    $this->post($deleteUrl, ['confirm' => false])->assertSessionHasErrors('confirm');
    expect($client->fresh()->revoked)->toBeFalse()->and(AuditLog::count())->toBe(0);
    $owner->forceFill(['email_verified_at' => null])->save();
    $this->get($confirmUrl)->assertRedirect('/email/verify');
    $this->post($deleteUrl, ['confirm' => true])->assertRedirect('/email/verify');
    $owner->forceFill(['email_verified_at' => now(), 'is_developer' => false])->save();
    $this->get($confirmUrl)->assertForbidden();
    $this->post($deleteUrl, ['confirm' => true])->assertForbidden();
    $this->actingAs(User::factory()->create(['is_developer' => true]))->get($confirmUrl)->assertForbidden();
    $this->post($deleteUrl, ['confirm' => true])->assertForbidden();
});

it('permanently revokes credentials and preserves other apps and audit history', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner, true);
    $other = oauthClientFixture($owner, true);
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, $owner, $client)))->assertOk()->json();
    $otherTokens = $this->postJson('/oauth/token', oauthExchange($other, oauthCode($this, $owner, $other)))->assertOk()->json();
    $pendingCode = oauthCode($this, $owner, $client);
    $history = AuditLog::where('client_id', $client->id)->count();
    $original = $client->fresh()->getRawOriginal();
    $this->withSession(['auth.password_confirmed_at' => now()->timestamp, 'developer.credentials.'.$client->id => Crypt::encryptString($client->plainSecret)])
        ->post(route('developer.apps.delete.store', $client), ['confirm' => true, 'owner_id' => 999, 'revoked' => false])
        ->assertRedirect(route('developer.apps.index'))->assertHeader('Cache-Control', 'no-store, private')
        ->assertSessionMissing('developer.credentials.'.$client->id);
    expect($client->fresh()->revoked)->toBeTrue()->and($client->fresh()->id)->toBe($client->id)
        ->and($client->fresh()->owner_id)->toBe($owner->id)->and($client->fresh()->secret)->toBe($original['secret'])
        ->and(oauthBearerWorks($tokens['access_token']))->toBeFalse()->and(oauthBearerWorks($otherTokens['access_token']))->toBeTrue()
        ->and(Passport::authCode()->newQuery()->where('client_id', $client->id)->where('revoked', false)->count())->toBe(0)
        ->and(Passport::token()->newQuery()->where('client_id', $client->id)->where('revoked', false)->count())->toBe(0)
        ->and(Passport::refreshToken()->newQuery()->whereIn('access_token_id', Passport::token()->newQuery()->where('client_id', $client->id)->select('id'))->where('revoked', false)->count())->toBe(0)
        ->and(AuditLog::where('client_id', $client->id)->count())->toBe($history + 1);
    $audit = AuditLog::where('event', OAuthAuditEvent::ClientDeleted)->sole();
    expect($audit->user_id)->toBe($owner->id)->and($audit->client_id)->toBe($client->id);
    $this->postJson('/oauth/token', oauthExchange($client, $pendingCode))->assertStatus(401);
    $this->postJson('/oauth/token', ['grant_type' => 'refresh_token', 'client_id' => $client->id, 'client_secret' => $client->plainSecret, 'refresh_token' => $tokens['refresh_token']])->assertStatus(401);
    $this->get(oauthAuthorizeUrl(oauthParameters($client)))->assertStatus(401);
    $this->get(route('developer.apps.index'))->assertViewHas('applications', fn ($apps): bool => $apps->total() === 1 && $apps->first()['id'] === $other->id);
    $this->withSession(['developer.credentials.'.$client->id => Crypt::encryptString($client->plainSecret)])
        ->get(route('developer.apps.show', $client))->assertForbidden()->assertDontSee($client->plainSecret);
    $this->get(route('developer.apps.edit', $client))->assertForbidden();
    $this->post(route('developer.apps.secret.store', $client), ['confirm' => true])->assertForbidden();
    $this->post(route('developer.apps.publish.store', $client), ['confirm' => true])->assertForbidden();
    $this->post(route('developer.apps.delete.store', $client), ['confirm' => true])->assertForbidden();
    $admin = User::factory()->create(['is_admin' => true, 'two_factor_secret' => Crypt::encryptString('test-only'), 'two_factor_confirmed_at' => now()]);
    $this->actingAs($admin)->get(route('admin.apps.show', $client))->assertOk()->assertSee('Revoked')->assertDontSee('Restore application');
    $this->post(route('admin.apps.restore', $client), ['confirm' => true])->assertForbidden();
    $this->get(route('admin.audit.index', ['event' => 'client.deleted', 'client_id' => $client->id]))->assertOk()->assertSee('client.deleted');
});

it('allows deletion in testing live and suspended states', function (OAuthClientStatus $status): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner, true);
    $client->forceFill(['status' => $status])->save();
    $this->actingAs($owner)->get(route('developer.apps.show', $client))->assertOk()->assertSee(route('developer.apps.delete.confirm', $client));
    $this->withSession(['auth.password_confirmed_at' => now()->timestamp])->post(route('developer.apps.delete.store', $client), ['confirm' => true])->assertRedirect(route('developer.apps.index'));
    expect($client->fresh()->revoked)->toBeTrue()->and($client->fresh()->status)->toBe($status);
})->with(OAuthClientStatus::cases());

it('rejects unsupported credential models non interactive apps and mismatched owner types', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $public = oauthClientFixture($owner);
    $public->forceFill(['app_type' => OAuthAppType::Web])->save();
    $confidentialSpa = oauthClientFixture($owner, true);
    $confidentialSpa->forceFill(['app_type' => OAuthAppType::Spa])->save();
    $machine = oauthClientFixture($owner, true);
    $machine->forceFill(['app_type' => OAuthAppType::Machine])->save();
    $foreign = oauthClientFixture($owner, true);
    $foreign->forceFill(['owner_type' => 'OtherOwner'])->save();
    $this->actingAs($owner)->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    foreach ([$public, $confidentialSpa, $machine, $foreign] as $client) {
        $this->get(route('developer.apps.delete.confirm', $client))->assertForbidden();
        $this->post(route('developer.apps.delete.store', $client), ['confirm' => true])->assertForbidden();
        expect($client->fresh()->revoked)->toBeFalse();
    }
});

it('rechecks current ownership and revocation under the lock', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner, true);
    $this->actingAs($owner);
    $client->newQuery()->whereKey($client->id)->update(['owner_id' => User::factory()->create()->id]);
    expect(fn () => app(DeleteApplication::class)->handle($client))->toThrow(AuthorizationException::class);
    $client->newQuery()->whereKey($client->id)->update(['owner_id' => $owner->id, 'revoked' => true]);
    expect(fn () => app(DeleteApplication::class)->handle($client))->toThrow(AuthorizationException::class);
    expect(AuditLog::count())->toBe(0);
});

it('rolls back revocation and credentials if auditing fails', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner, true);
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, $owner, $client)))->assertOk()->json();
    AuditLog::creating(function (AuditLog $log): void {
        if ($log->event === OAuthAuditEvent::ClientDeleted) {
            throw new RuntimeException('Test audit failure');
        }
    });
    expect(fn () => app(DeleteApplication::class)->handle($client))->toThrow(RuntimeException::class);
    expect($client->fresh()->revoked)->toBeFalse()->and(oauthBearerWorks($tokens['access_token']))->toBeTrue()
        ->and(AuditLog::where('event', OAuthAuditEvent::ClientDeleted)->count())->toBe(0);
});

it('revokes credentials across batch boundaries', function (): void {
    $owner = User::factory()->create(['is_developer' => true]);
    $client = oauthClientFixture($owner, true);
    $tokens = [];
    $refreshTokens = [];
    foreach (range(1, 501) as $number) {
        $identifier = str_pad((string) $number, 80, '0', STR_PAD_LEFT);
        $tokens[] = ['id' => $identifier, 'client_id' => $client->id, 'scopes' => '[]', 'revoked' => false, 'expires_at' => now()->addHour()];
        $refreshTokens[] = ['id' => $identifier, 'access_token_id' => $identifier, 'revoked' => false, 'expires_at' => now()->addDay()];
    }
    DB::table('oauth_access_tokens')->insert($tokens);
    DB::table('oauth_refresh_tokens')->insert($refreshTokens);
    $this->actingAs($owner);
    app(DeleteApplication::class)->handle($client);
    expect(Passport::token()->newQuery()->where('revoked', false)->count())->toBe(0)
        ->and(Passport::refreshToken()->newQuery()->where('revoked', false)->count())->toBe(0);
});
