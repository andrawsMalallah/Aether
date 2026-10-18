<?php

namespace App\Actions\OAuth;

use App\Enums\OAuthAuditEvent;
use App\Models\AuditLog;
use App\Models\Consent;
use App\Models\OAuthClient;
use App\Models\User;
use App\Notifications\ApplicationApproved;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use Psr\Http\Message\ResponseInterface;

class CompleteConsent
{
    public function handle(AuthorizationRequestInterface $authorization, User $user, bool $approved, ResponseInterface $response): ResponseInterface
    {
        if ((string) $user->getKey() !== (string) $authorization->getUser()?->getIdentifier()) {
            throw OAuthServerException::accessDenied();
        }

        return DB::transaction(function () use ($authorization, $user, $approved, $response): ResponseInterface {
            $client = OAuthClient::query()->whereKey($authorization->getClient()->getIdentifier())->lockForUpdate()->firstOrFail();
            Gate::forUser($user)->authorize('authorize', $client);
            $authorization->setAuthorizationApproved($approved);
            $result = app(AuthorizationServer::class)->completeAuthorizationRequest($authorization, $response);
            // Persist only after the library has successfully issued a code for this approval.
            $scopes = array_map(fn ($scope): string => $scope->getIdentifier(), $authorization->getScopes());
            $consent = Consent::query()->where('user_id', $user->getKey())->where('client_id', $client->getKey())->lockForUpdate()->first();
            $granted = $consent && ! $consent->revoked_at ? $consent->scopes : [];
            Consent::query()->updateOrCreate(['user_id' => $user->getKey(), 'client_id' => $client->getKey()], [
                'scopes' => array_values(array_unique([...$granted, ...$scopes])),
                'granted_at' => now(),
                'revoked_at' => null,
            ]);
            AuditLog::query()->create(['user_id' => $user->getKey(), 'client_id' => $client->getKey(), 'event' => OAuthAuditEvent::ConsentGranted]);

            $permissions = array_map(fn (string $scope): string => config('oauth.scopes.'.$scope, $scope), $scopes);
            $notification = new ApplicationApproved($client->name, $permissions, now()->utc()->format('Y-m-d H:i:s').' UTC');
            // No email for rolled-back grants, denied requests or automatic saved consent.
            DB::afterCommit(fn () => $user->notify($notification));

            return $result;
        });
    }
}
