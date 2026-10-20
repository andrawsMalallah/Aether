<?php

use App\Enums\OAuthAuditEvent;
use App\Enums\OAuthClientStatus;
use App\Models\AuditLog;
use App\Models\User;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Laravel\Passport\Passport;

uses(RefreshDatabase::class);

it('authenticates the current confidential client inside the client transaction before revocation', function (): void {
    $client = oauthClientFixture(confidential: true);
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, User::factory()->create(), $client)))->assertOk()->json();
    $baseline = DB::transactionLevel();
    $clientReadInsideTransaction = false;
    DB::listen(function (QueryExecuted $query) use ($baseline, &$clientReadInsideTransaction): void {
        if (str_starts_with($query->sql, 'select') && str_contains($query->sql, 'oauth_clients')) {
            $clientReadInsideTransaction = $query->connection->transactionLevel() > $baseline;
        }
    });
    $realHasher = Hash::getFacadeRoot();
    Hash::shouldReceive('check')->once()->andReturnUsing(function (string $value, string $hash) use ($realHasher, $baseline, &$clientReadInsideTransaction): bool {
        expect(DB::transactionLevel())->toBeGreaterThan($baseline)
            ->and($clientReadInsideTransaction)->toBeTrue();

        return $realHasher->check($value, $hash);
    });
    try {
        $this->post('/oauth/revoke', ['client_id' => $client->id, 'client_secret' => $client->plainSecret, 'token' => $tokens['access_token']])->assertOk()->assertContent('');
    } finally {
        Hash::swap($realHasher);
    }
    expect(Passport::token()->newQuery()->sole()->revoked)->toBeTrue()
        ->and(Passport::refreshToken()->newQuery()->sole()->revoked)->toBeTrue();
});

it('preserves pair-scoped revocation after a refresh has already committed', function (string $type): void {
    $client = oauthClientFixture();
    $user = User::factory()->create();
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, $user, $client)))->assertOk()->json();
    $independent = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, $user, $client)))->assertOk()->json();
    $refresh = ['grant_type' => 'refresh_token', 'client_id' => $client->id];
    $successor = $this->postJson('/oauth/token', [...$refresh, 'refresh_token' => $tokens['refresh_token']])->assertOk()->json();
    $data = ['client_id' => $client->id, 'token' => $tokens[$type]];
    $this->post('/oauth/revoke', $data)->assertOk()->assertContent('');
    $this->post('/oauth/revoke', $data)->assertOk()->assertContent('');
    expect(oauthBearerWorks($successor['access_token']))->toBeTrue()
        ->and(oauthBearerWorks($independent['access_token']))->toBeTrue()
        ->and(AuditLog::where('event', OAuthAuditEvent::TokenRevoked)->count())->toBe(2);
    $this->postJson('/oauth/token', [...$refresh, 'refresh_token' => $successor['refresh_token']])->assertOk();
})->with(['access_token', 'refresh_token']);

it('permits cleanup for suspended and retained revoked clients without allowing issuance', function (string $state, string $type): void {
    $client = oauthClientFixture(confidential: true);
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, User::factory()->create(), $client)))->assertOk()->json();
    $client->forceFill($state === 'suspended' ? ['status' => OAuthClientStatus::Suspended] : ['revoked' => true])->save();
    $this->post('/oauth/revoke', ['client_id' => $client->id, 'client_secret' => $client->plainSecret, 'token' => $tokens[$type]])->assertOk()->assertContent('');
    expect(Passport::token()->newQuery()->sole()->revoked)->toBeTrue()
        ->and(Passport::refreshToken()->newQuery()->sole()->revoked)->toBeTrue();
    $this->postJson('/oauth/token', ['grant_type' => 'refresh_token', 'client_id' => $client->id, 'client_secret' => $client->plainSecret, 'refresh_token' => $tokens['refresh_token']])->assertUnauthorized();
})->with([['suspended', 'access_token'], ['suspended', 'refresh_token'], ['revoked', 'access_token'], ['revoked', 'refresh_token']]);

it('supports Basic authentication and rejects stale secrets without revoking credentials', function (): void {
    $client = oauthClientFixture(confidential: true);
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, User::factory()->create(), $client)))->assertOk()->json();
    $oldSecret = $client->plainSecret;
    $newSecret = Str::random(40);
    $client->forceFill(['secret' => $newSecret])->save();
    $this->post('/oauth/revoke', ['token' => $tokens['access_token']], ['Authorization' => 'Basic '.base64_encode($client->id.':'.$oldSecret)])->assertUnauthorized();
    expect(oauthBearerWorks($tokens['access_token']))->toBeTrue();
    $headers = ['Authorization' => 'Basic '.base64_encode($client->id.':'.$newSecret)];
    $this->post('/oauth/revoke', ['client_id' => $client->id, 'token' => $tokens['access_token']], $headers)->assertStatus(400);
    expect(oauthBearerWorks($tokens['access_token']))->toBeTrue();
    $this->post('/oauth/revoke', ['token' => $tokens['access_token']], $headers)->assertOk()->assertContent('');
    expect(oauthBearerWorks($tokens['access_token']))->toBeFalse();
});

it('rolls back both credential revocations when audit persistence fails', function (string $type): void {
    $client = oauthClientFixture();
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, User::factory()->create(), $client)))->assertOk()->json();
    $data = ['client_id' => $client->id, 'token' => $tokens[$type]];
    AuditLog::creating(function (AuditLog $audit): void {
        if ($audit->event === OAuthAuditEvent::TokenRevoked) {
            throw new RuntimeException('Synthetic revocation audit failure');
        }
    });
    try {
        $this->post('/oauth/revoke', $data)->assertServerError();
        expect(Passport::token()->newQuery()->sole()->revoked)->toBeFalse()
            ->and(Passport::refreshToken()->newQuery()->sole()->revoked)->toBeFalse()
            ->and(AuditLog::where('event', OAuthAuditEvent::TokenRevoked)->count())->toBe(0);
    } finally {
        AuditLog::flushEventListeners();
    }
    $this->post('/oauth/revoke', $data)->assertOk();
    expect(Passport::token()->newQuery()->sole()->revoked)->toBeTrue()
        ->and(Passport::refreshToken()->newQuery()->sole()->revoked)->toBeTrue()
        ->and(AuditLog::where('event', OAuthAuditEvent::TokenRevoked)->count())->toBe(1);
})->with(['access_token', 'refresh_token']);
