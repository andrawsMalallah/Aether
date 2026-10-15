<?php

namespace App\Actions\Developer;

use App\Enums\OAuthAuditEvent;
use App\Models\AuditLog;
use App\Models\OAuthClient;
use App\Services\OAuth\RevokeClientCredentials;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Laravel\Passport\ClientRepository;

class RegenerateApplicationSecret
{
    public function __construct(private ClientRepository $clients, private RevokeClientCredentials $revoke) {}

    public function handle(OAuthClient $application): OAuthClient
    {
        return DB::transaction(function () use ($application): OAuthClient {
            $client = OAuthClient::query()->whereKey($application->id)->lockForUpdate()->firstOrFail();
            Gate::authorize('regenerateSecret', $client);
            $this->clients->regenerateSecret($client);
            $this->revoke->handle($client);
            AuditLog::create(['user_id' => auth()->id(), 'client_id' => $client->id, 'event' => OAuthAuditEvent::ClientSecretRegenerated]);

            return $client;
        });
    }
}
