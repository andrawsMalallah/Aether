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

    /** @param array{app_type: string, name: string, homepage_url?: string|null, redirect_uris?: list<string>, scopes?: list<string>} $data */
    public function handle(User $user, array $data): OAuthClient
    {
        Gate::authorize('create', OAuthClient::class);

        return DB::transaction(function () use ($user, $data): OAuthClient {
            $user = User::whereKey($user->id)->lockForUpdate()->firstOrFail();
            abort_unless($user->accountAvailable() && $user->hasVerifiedEmail() && $user->is_developer, 403);
            $appType = OAuthAppType::from($data['app_type']);
            abort_unless(in_array($appType, [OAuthAppType::Web, OAuthAppType::Spa, OAuthAppType::Mobile, OAuthAppType::Machine], true), 403);
            /** @var OAuthClient $client */
            $client = $appType === OAuthAppType::Machine
                ? $this->clients->createClientCredentialsGrantClient($data['name'])
                : $this->clients->createAuthorizationCodeGrantClient($data['name'], $data['redirect_uris'] ?? [], $appType === OAuthAppType::Web, $user);
            $client->owner()->associate($user);
            // Ownership/grants/trust are assigned server-side, independent of form input.
            $client->forceFill([
                'homepage_url' => $data['homepage_url'] ?? null,
                'app_type' => $appType, 'status' => OAuthClientStatus::Testing,
                'allowed_scopes' => $appType === OAuthAppType::Machine ? [] : ($data['scopes'] ?? []),
                'first_party' => false, 'introspection_client_ids' => null,
            ])->save();
            AuditLog::create(['user_id' => $user->id, 'client_id' => $client->id, 'event' => OAuthAuditEvent::ClientCreated]);

            return $client;
        });
    }
}
