<?php

namespace App\Actions\Developer;

use App\Enums\OAuthAppType;
use App\Enums\OAuthAuditEvent;
use App\Enums\OAuthClientStatus;
use App\Models\AuditLog;
use App\Models\OAuthClient;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Laravel\Passport\ClientRepository;

class RegisterApplication
{
    public function __construct(private ClientRepository $clients) {}

    /** @param array{name: string, homepage_url?: string|null, redirect_uris: list<string>, scopes: list<string>} $data */
    public function handle(User $user, array $data): OAuthClient
    {
        Gate::authorize('create', OAuthClient::class);

        return DB::transaction(function () use ($user, $data): OAuthClient {
            /** @var OAuthClient $client */
            $client = $this->clients->createAuthorizationCodeGrantClient($data['name'], $data['redirect_uris'], true, $user);
            // Ownership/grants/trust are assigned server-side, independent of form input.
            $client->forceFill([
                'homepage_url' => $data['homepage_url'] ?? null,
                'app_type' => OAuthAppType::Web, 'status' => OAuthClientStatus::Testing,
                'allowed_scopes' => $data['scopes'], 'first_party' => false, 'introspection_client_ids' => null,
            ])->save();
            AuditLog::create(['user_id' => $user->id, 'client_id' => $client->id, 'event' => OAuthAuditEvent::ClientCreated]);

            return $client;
        });
    }
}
