<?php

namespace App\Actions\Developer;

use App\Enums\OAuthAppType;
use App\Enums\OAuthAuditEvent;
use App\Models\AuditLog;
use App\Models\OAuthClient;
use App\Services\PrivateStorage;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Laravel\Passport\Passport;

class UpdateApplication
{
    /** @param array{name: string, homepage_url?: string|null, redirect_uris?: list<string>, scopes?: list<string>, logo?: UploadedFile|null} $data */
    public function handle(OAuthClient $application, array $data): void
    {
        DB::transaction(function () use ($application, $data): void {
            $client = OAuthClient::query()->whereKey($application->id)->lockForUpdate()->firstOrFail();
            Gate::authorize('update', $client);
            if (isset($data['logo'])) {
                $logoPath = $data['logo']->store('oauth-client-logos', PrivateStorage::name());
                abort_if($logoPath === false, 500, 'The logo could not be stored. Please try again.');
                // Retain previous private files; only the current database reference is served.
                $client->logo_path = $logoPath;
            }
            $client->forceFill([
                'name' => $data['name'], 'homepage_url' => $data['homepage_url'] ?? null,
            ]);
            // Machine API permissions belong to administrators, never owner settings.
            if ($client->app_type !== OAuthAppType::Machine) {
                $client->forceFill(['redirect_uris' => $data['redirect_uris'] ?? [], 'allowed_scopes' => $data['scopes'] ?? []]);
            }
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
