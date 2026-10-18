<?php

namespace App\Actions\Admin;

use App\Enums\OAuthAuditEvent;
use App\Models\AuditLog;
use App\Models\OAuthClient;
use App\Services\OAuth\RevokeClientCredentials;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;

class RevokeApplicationTokens
{
    public function __construct(private RevokeClientCredentials $revoke) {}

    public function handle(OAuthClient $application): void
    {
        DB::transaction(function () use ($application): void {
            $client = OAuthClient::query()->whereKey($application->id)->lockForUpdate()->firstOrFail();
            Gate::authorize('revokeTokens', $client);
            // Share issuance's client lock without changing availability or future grants.
            $this->revoke->handle($client);
            AuditLog::create(['user_id' => auth()->id(), 'client_id' => $client->id, 'event' => OAuthAuditEvent::ClientTokensRevoked]);
        });
    }
}
