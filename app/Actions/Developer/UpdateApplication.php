<?php

namespace App\Actions\Developer;

use App\Enums\OAuthAuditEvent;
use App\Models\AuditLog;
use App\Models\OAuthClient;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Laravel\Passport\Passport;

class UpdateApplication
{
    /** @param array{name: string, homepage_url?: string|null, redirect_uris: list<string>, scopes: list<string>} $data */
    public function handle(OAuthClient $application, array $data): void
    {
        DB::transaction(function () use ($application, $data): void {
            $client = OAuthClient::query()->whereKey($application->id)->lockForUpdate()->firstOrFail();
            Gate::authorize('update', $client);
            $client->forceFill([
                'name' => $data['name'], 'homepage_url' => $data['homepage_url'] ?? null,
                'redirect_uris' => $data['redirect_uris'], 'allowed_scopes' => $data['scopes'],
            ]);
            if ($client->isDirty()) {
                // Already-issued codes otherwise retain their original redirect until expiry.
                if ($client->isDirty('redirect_uris')) {
                    Passport::authCode()->newQuery()->where('client_id', $client->id)
                        ->where('revoked', false)->update(['revoked' => true]);
                }
                $client->save();
                AuditLog::create(['user_id' => auth()->id(), 'client_id' => $client->id, 'event' => OAuthAuditEvent::ClientUpdated]);
            }
        });
    }
}
