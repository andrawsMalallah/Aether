<?php

namespace App\Actions\Developer;

use App\Enums\OAuthAuditEvent;
use App\Enums\OAuthClientStatus;
use App\Models\AuditLog;
use App\Models\OAuthClient;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;

class PublishApplication
{
    public function handle(OAuthClient $application): void
    {
        DB::transaction(function () use ($application): void {
            $client = OAuthClient::query()->whereKey($application->id)->lockForUpdate()->firstOrFail();
            Gate::authorize('publish', $client);
            $client->forceFill(['status' => OAuthClientStatus::Live])->save();
            AuditLog::create(['user_id' => auth()->id(), 'client_id' => $client->id, 'event' => OAuthAuditEvent::ClientPublished]);
        });
    }
}
