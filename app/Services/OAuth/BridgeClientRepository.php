<?php

namespace App\Services\OAuth;

use App\Enums\OAuthAppType;
use App\Models\OAuthClient;
use Laravel\Passport\Bridge\Client;
use Laravel\Passport\Bridge\ClientRepository;
use League\OAuth2\Server\Entities\ClientEntityInterface;

class BridgeClientRepository extends ClientRepository
{
    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        $client = $this->clients->findActive($clientIdentifier);
        if (! $client instanceof OAuthClient) {
            return null;
        }

        app(TokenContext::class)->clientId = $clientIdentifier;
        $entity = new Client($client->getKey(), $client->name, $client->redirect_uris, $client->confidential(), $client->provider, $client->grant_types);
        // Grant permissions derive from both the stored grants and the application's type.
        $entity->grantTypes = array_values(array_intersect($client->grant_types, match ($client->app_type) {
            OAuthAppType::Machine => $client->confidential() ? ['client_credentials'] : [],
            OAuthAppType::Web => $client->confidential() ? ['authorization_code', 'refresh_token'] : [],
            OAuthAppType::Spa, OAuthAppType::Mobile => ! $client->confidential() ? ['authorization_code', 'refresh_token'] : [],
        }));

        return $entity;
    }
}
