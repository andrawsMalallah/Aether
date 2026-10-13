<?php

namespace App\Services\OAuth;

use App\Enums\OAuthClientStatus;
use App\Models\OAuthClient;
use App\Models\User;
use Laravel\Passport\Bridge\ScopeRepository as PassportScopeRepository;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;

class ScopeRepository extends PassportScopeRepository
{
    /** @param ScopeEntityInterface[] $scopes
     * @return ScopeEntityInterface[]
     */
    public function finalizeScopes(array $scopes, string $grantType, ClientEntityInterface $clientEntity, ?string $userIdentifier = null, ?string $authCodeId = null): array
    {
        $client = $this->clients->findActive($clientEntity->getIdentifier());
        if (! $client instanceof OAuthClient) {
            throw OAuthServerException::unauthorizedClient();
        }
        if ($userIdentifier !== null) {
            $user = User::query()->find($userIdentifier);
            if (! $user || ! $client->acceptsUser($user)) {
                throw OAuthServerException::accessDenied();
            }
        } elseif ($client->status !== OAuthClientStatus::Live) {
            // There is no signed-in owner in a machine-to-machine exchange.
            throw OAuthServerException::unauthorizedClient();
        }
        foreach ($scopes as $scope) {
            if (! $client->hasScope($scope->getIdentifier()) || ! array_key_exists($scope->getIdentifier(), config('oauth.scopes'))) {
                throw OAuthServerException::invalidScope($scope->getIdentifier());
            }
        }
        if ($authCodeId !== null) {
            app(TokenContext::class)->authCodeId = $authCodeId;
        }

        return $scopes;
    }
}
