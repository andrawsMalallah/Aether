<?php

namespace App\Actions\Developer;

use App\Enums\OAuthAuditEvent;
use App\Models\AuditLog;
use App\Models\OAuthClient;
use App\Services\OAuth\RevokeClientCredentials;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;

class DeleteApplication
{
    public function __construct(private RevokeClientCredentials $revoke) {}

    public function handle(OAuthClient $application): void
    {
        DB::transaction(function () use ($application): void {
            $client = OAuthClient::query()->whereKey($application->id)->lockForUpdate()->firstOrFail();
            Gate::authorize('delete', $client);
            // Retain the client ID and audit references; revoked clients cannot be restored.
            $client->forceFill(['revoked' => true])->save();
            $this->revoke->handle($client);
            AuditLog::create(['user_id' => auth()->id(), 'client_id' => $client->id, 'event' => OAuthAuditEvent::ClientDeleted]);
        });
    }
}
