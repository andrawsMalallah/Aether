<?php

use App\Enums\OAuthAppType;
use App\Enums\OAuthAuditEvent;
use App\Enums\OAuthClientStatus;
use App\Models\AuditLog;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Notification;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    Notification::fake();
});

it('audits successful code issuance and refresh once with credential-owner references only', function (): void {
    $owner = User::factory()->create();
    $client = oauthClientFixture();
    $code = oauthCode($this, $owner, $client);
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, $code))->assertOk()->json();
    $audit = AuditLog::where('event', OAuthAuditEvent::TokenIssued)->sole();
    expect($audit->user_id)->toBe($owner->id)->and($audit->client_id)->toBe($client->id)
        ->and(array_keys($audit->getAttributes()))->toBe(['id', 'user_id', 'client_id', 'event', 'created_at']);
    $refresh = ['grant_type' => 'refresh_token', 'client_id' => $client->id, 'refresh_token' => $tokens['refresh_token']];
    $this->postJson('/oauth/token', $refresh)->assertOk();
    $this->postJson('/oauth/token', $refresh)->assertStatus(400);
    expect(AuditLog::where('event', OAuthAuditEvent::TokenIssued)->count())->toBe(1)
        ->and(AuditLog::where('event', OAuthAuditEvent::TokenRefreshed)->count())->toBe(1)
        ->and(AuditLog::where('event', OAuthAuditEvent::RefreshReplayed)->count())->toBe(1)
        ->and(AuditLog::get()->toJson())->not->toContain($code, $tokens['access_token'], $tokens['refresh_token']);
});

it('audits machine issuance without inventing an authenticated user and excludes rejected requests', function (): void {
    $client = app(ClientRepository::class)->createClientCredentialsGrantClient('Audit service');
    $client->forceFill(['app_type' => OAuthAppType::Machine, 'status' => OAuthClientStatus::Live, 'allowed_scopes' => ['stats:read']])->save();
    $parameters = ['grant_type' => 'client_credentials', 'client_id' => $client->id, 'client_secret' => $client->plainSecret, 'scope' => 'stats:read'];
    $this->postJson('/oauth/token', [...$parameters, 'client_secret' => 'invalid'])->assertUnauthorized();
    expect(AuditLog::count())->toBe(0);
    $this->postJson('/oauth/token', $parameters)->assertOk();
    $audit = AuditLog::sole();
    expect($audit->event)->toBe(OAuthAuditEvent::TokenIssued)->and($audit->user_id)->toBeNull()->and($audit->client_id)->toBe($client->id);
    $this->postJson('/oauth/token', [...$parameters, 'scope' => 'email'])->assertStatus(400);
    expect(AuditLog::count())->toBe(1);
});

it('rolls back credentials and code consumption when issuance auditing fails', function (): void {
    $user = User::factory()->create();
    $client = oauthClientFixture();
    $code = oauthCode($this, $user, $client);
    AuditLog::creating(function (AuditLog $audit): void {
        if ($audit->event === OAuthAuditEvent::TokenIssued) {
            throw new RuntimeException('Synthetic issuance audit failure');
        }
    });
    try {
        $this->postJson('/oauth/token', oauthExchange($client, $code))->assertServerError();
        expect(Passport::token()->newQuery()->count())->toBe(0)
            ->and(Passport::authCode()->newQuery()->sole()->revoked)->toBeFalse()
            ->and(AuditLog::where('event', OAuthAuditEvent::TokenIssued)->count())->toBe(0);
    } finally {
        AuditLog::flushEventListeners();
    }
    $this->postJson('/oauth/token', oauthExchange($client, $code))->assertOk();
    expect(AuditLog::where('event', OAuthAuditEvent::TokenIssued)->count())->toBe(1);
});
