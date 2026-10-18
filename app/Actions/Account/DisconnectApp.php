<?php

namespace App\Actions\Account;

use App\Enums\OAuthAuditEvent;
use App\Models\AuditLog;
use App\Models\Consent;
use App\Models\OAuthClient;
use App\Models\User;
use App\Services\OAuth\RevokeUserClientCredentials;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;

class DisconnectApp
{
    public function __construct(private RevokeUserClientCredentials $revoke) {}

    public function handle(User $user, Consent $consent): void
    {
        Gate::forUser($user)->authorize('disconnect', $consent);
        DB::transaction(function () use ($user, $consent): void {
            // Lock client before consent, just like explicit consent and token issuance.
            $client = OAuthClient::query()->whereKey($consent->client_id)->lockForUpdate()->firstOrFail();
            $current = Consent::query()->whereKey($consent->id)->where('client_id', $client->id)->where('user_id', $user->id)->lockForUpdate()->firstOrFail();
            Gate::forUser($user)->authorize('disconnect', $current);
            $this->revoke->handle($user, $client);
            $current->forceFill(['revoked_at' => now()])->save();
            AuditLog::create(['user_id' => $user->id, 'client_id' => $client->id, 'event' => OAuthAuditEvent::ConsentRevoked]);
        });
    }
}
