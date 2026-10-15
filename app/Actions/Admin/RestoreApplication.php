<?php

namespace App\Actions\Admin;

use App\Enums\OAuthAuditEvent;
use App\Enums\OAuthClientStatus;
use App\Models\AuditLog;
use App\Models\OAuthClient;
use App\Services\OAuth\RevokeClientCredentials;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;

class RestoreApplication
{
    public function __construct(private RevokeClientCredentials $revoke) {}

    public function handle(OAuthClient $application): void
    {
        DB::transaction(function () use ($application): void {
            $client = OAuthClient::query()->whereKey($application->id)->lockForUpdate()->firstOrFail();
            Gate::authorize('restore', $client);
            // Also invalidate legacy credentials if suspension predates the admin revocation flow.
            $this->revoke->handle($client);
            $client->forceFill(['status' => OAuthClientStatus::Testing])->save();
            AuditLog::create(['user_id' => auth()->id(), 'client_id' => $client->id, 'event' => OAuthAuditEvent::ClientRestored]);
        });
    }
}
