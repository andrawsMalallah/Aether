<?php

use App\Enums\OAuthAppType;
use App\Enums\OAuthAuditEvent;
use App\Models\AuditLog;
use App\Models\User;
use App\Services\OAuth\ReadToken;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\Passport;

uses(RefreshDatabase::class);

it('revokes the active successor family after refresh reuse without disturbing independent grants', function (string $type): void {
    $user = User::factory()->create();
    $client = oauthClientFixture(confidential: $type === 'web');
    $client->forceFill(['app_type' => OAuthAppType::from($type)])->save();
    $issue = fn ($owner, $application): array => $this->postJson('/oauth/token', oauthExchange($application, oauthCode($this, $owner, $application, 'openid email')))->assertOk()->json();
    $original = $issue($user, $client);
    $independent = $issue($user, $client);
    $otherUser = $issue(User::factory()->create(), $client);
    $otherClient = oauthClientFixture();
    $otherApplication = $issue($user, $otherClient);
    $refresh = ['grant_type' => 'refresh_token', 'client_id' => $client->id,
        ...($client->plainSecret ? ['client_secret' => $client->plainSecret] : [])];
    $replacement = $this->postJson('/oauth/token', [...$refresh, 'refresh_token' => $original['refresh_token'], 'scope' => 'openid'])->assertOk()->json();
    $successor = $this->postJson('/oauth/token', [...$refresh, 'refresh_token' => $replacement['refresh_token']])->assertOk()->json();
    expect(oauthBearerWorks($successor['access_token']))->toBeTrue();
    $issuedCount = AuditLog::where('event', OAuthAuditEvent::TokenIssued)->count();
    $refreshedCount = AuditLog::where('event', OAuthAuditEvent::TokenRefreshed)->count();
    $this->postJson('/oauth/token', [...$refresh, 'refresh_token' => $original['refresh_token']])
        ->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
    expect(oauthBearerWorks($successor['access_token']))->toBeFalse()
        ->and(AuditLog::where('event', OAuthAuditEvent::RefreshReplayed)->count())->toBe(1)
        ->and(AuditLog::where('event', OAuthAuditEvent::TokenIssued)->count())->toBe($issuedCount)
        ->and(AuditLog::where('event', OAuthAuditEvent::TokenRefreshed)->count())->toBe($refreshedCount);
    $this->postJson('/oauth/token', [...$refresh, 'refresh_token' => $successor['refresh_token']])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
    foreach ([$independent, $otherUser, $otherApplication] as $unrelated) {
        expect(oauthBearerWorks($unrelated['access_token']))->toBeTrue();
    }
    $this->postJson('/oauth/token', [...$refresh, 'refresh_token' => $independent['refresh_token']])->assertOk();
})->with(['browser' => 'spa', 'mobile' => 'mobile', 'web' => 'web']);

it('retains replay lineage after authorization code cleanup and rejects foreign-client reuse without revocation', function (): void {
    $client = oauthClientFixture();
    $original = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, User::factory()->create(), $client)))->assertOk()->json();
    $refresh = ['grant_type' => 'refresh_token', 'client_id' => $client->id];
    $successor = $this->postJson('/oauth/token', [...$refresh, 'refresh_token' => $original['refresh_token']])->assertOk()->json();
    $this->postJson('/oauth/token', [...$refresh, 'client_id' => oauthClientFixture()->id, 'refresh_token' => $original['refresh_token']])->assertStatus(400);
    expect(oauthBearerWorks($successor['access_token']))->toBeTrue()
        ->and(AuditLog::where('event', OAuthAuditEvent::RefreshReplayed)->count())->toBe(0);
    Passport::authCode()->newQuery()->delete(); // Simulate the existing expired-code cleanup boundary.
    $this->postJson('/oauth/token', [...$refresh, 'refresh_token' => $original['refresh_token']])->assertStatus(400);
    expect(oauthBearerWorks($successor['access_token']))->toBeFalse()
        ->and(Passport::refreshToken()->newQuery()->where('revoked', false)->exists())->toBeFalse();
});

it('rejects missing legacy lineage without grouping unrelated null families', function (?string $lineage, bool $revoked): void {
    $client = oauthClientFixture();
    $user = User::factory()->create();
    $original = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, $user, $client, 'profile')))->assertOk()->json();
    $unrelated = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, $user, $client, 'profile')))->assertOk()->json();
    Passport::token()->newQuery()->update(['auth_code_id' => $lineage]);
    $originalAccessId = app(ReadToken::class)->access($original['access_token']);
    Passport::refreshToken()->newQuery()->where('access_token_id', $originalAccessId)->update(['revoked' => $revoked]);
    $before = Passport::token()->newQuery()->count();
    $this->postJson('/oauth/token', ['grant_type' => 'refresh_token', 'client_id' => $client->id, 'refresh_token' => $original['refresh_token']])
        ->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
    expect(Passport::token()->newQuery()->count())->toBe($before)
        ->and(oauthBearerWorks($unrelated['access_token']))->toBeTrue();
})->with([[null, false], ['', false], [null, true]]);

it('revokes refresh and access rows beyond the family batch boundary', function (): void {
    $client = oauthClientFixture();
    $user = User::factory()->create();
    $original = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, $user, $client)))->assertOk()->json();
    $access = Passport::token()->newQuery()->sole();
    Passport::refreshToken()->newQuery()->update(['revoked' => true]);
    $accessRows = [];
    $refreshRows = [];
    foreach (range(0, 500) as $number) {
        $identifier = str_pad(dechex($number), 80, '0', STR_PAD_LEFT);
        $accessRows[] = ['id' => $identifier, 'user_id' => $user->id, 'client_id' => $client->id,
            'auth_code_id' => $access->auth_code_id, 'scopes' => '[]', 'revoked' => $number === 0, 'expires_at' => now()->addHour()];
        $refreshRows[] = ['id' => $identifier, 'access_token_id' => $identifier, 'revoked' => false, 'expires_at' => now()->addDay()];
    }
    DB::table('oauth_access_tokens')->insert($accessRows);
    DB::table('oauth_refresh_tokens')->insert($refreshRows);
    $this->postJson('/oauth/token', ['grant_type' => 'refresh_token', 'client_id' => $client->id, 'refresh_token' => $original['refresh_token']])->assertStatus(400);
    expect(Passport::token()->newQuery()->where('revoked', false)->exists())->toBeFalse()
        ->and(Passport::refreshToken()->newQuery()->where('revoked', false)->exists())->toBeFalse();
});

it('scopes family revocation to both the stored client and account even if lineage identifiers collide', function (): void {
    $user = User::factory()->create();
    $client = oauthClientFixture();
    $original = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, $user, $client)))->assertOk()->json();
    $family = Passport::token()->newQuery()->sole()->auth_code_id;
    $otherUser = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, User::factory()->create(), $client)))->assertOk()->json();
    $otherClient = oauthClientFixture();
    $otherApplication = $this->postJson('/oauth/token', oauthExchange($otherClient, oauthCode($this, $user, $otherClient)))->assertOk()->json();
    // Corrupt only isolated fixture metadata to verify the defensive owner/client bounds.
    Passport::token()->newQuery()->update(['auth_code_id' => $family]);
    $refresh = ['grant_type' => 'refresh_token', 'client_id' => $client->id, 'refresh_token' => $original['refresh_token']];
    $successor = $this->postJson('/oauth/token', $refresh)->assertOk()->json();
    $this->postJson('/oauth/token', $refresh)->assertStatus(400);
    expect(oauthBearerWorks($successor['access_token']))->toBeFalse()
        ->and(oauthBearerWorks($otherUser['access_token']))->toBeTrue()
        ->and(oauthBearerWorks($otherApplication['access_token']))->toBeTrue();
});

it('rejects refresh credentials whose persisted owner is missing', function (): void {
    $client = oauthClientFixture();
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, User::factory()->create(), $client, 'profile')))->assertOk()->json();
    Passport::token()->newQuery()->update(['user_id' => null]);
    $this->postJson('/oauth/token', ['grant_type' => 'refresh_token', 'client_id' => $client->id, 'refresh_token' => $tokens['refresh_token']])
        ->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
    expect(Passport::token()->newQuery()->count())->toBe(1);
});

it('rolls back family revocation when replay auditing fails and revokes on a successful retry', function (): void {
    $client = oauthClientFixture();
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, User::factory()->create(), $client)))->assertOk()->json();
    $refresh = ['grant_type' => 'refresh_token', 'client_id' => $client->id, 'refresh_token' => $tokens['refresh_token']];
    $successor = $this->postJson('/oauth/token', $refresh)->assertOk()->json();
    AuditLog::creating(function (AuditLog $audit): void {
        if ($audit->event === OAuthAuditEvent::RefreshReplayed) {
            throw new RuntimeException('Synthetic replay audit failure');
        }
    });
    try {
        $this->postJson('/oauth/token', $refresh)->assertServerError();
        expect(oauthBearerWorks($successor['access_token']))->toBeTrue()
            ->and(Passport::refreshToken()->newQuery()->where('revoked', false)->count())->toBe(1)
            ->and(AuditLog::where('event', OAuthAuditEvent::RefreshReplayed)->count())->toBe(0);
    } finally {
        AuditLog::flushEventListeners();
    }
    $this->postJson('/oauth/token', $refresh)->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
    expect(oauthBearerWorks($successor['access_token']))->toBeFalse()
        ->and(Passport::refreshToken()->newQuery()->where('revoked', false)->count())->toBe(0)
        ->and(AuditLog::where('event', OAuthAuditEvent::RefreshReplayed)->count())->toBe(1);
});
