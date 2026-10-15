<?php

namespace App\Policies;

use App\Enums\OAuthAppType;
use App\Enums\OAuthClientStatus;
use App\Models\OAuthClient;
use App\Models\User;

class OAuthClientPolicy
{
    public function introspectToken(?User $user, OAuthClient $client): bool
    {
        return $client->available() && $client->status === OAuthClientStatus::Live
            && $client->confidential() && $client->app_type === OAuthAppType::Web
            && ($client->introspection_client_ids ?? []) !== [];
    }

    public function revokeToken(?User $user, OAuthClient $client, string $authenticatedClientId): bool
    {
        return $client->getKey() === $authenticatedClientId;
    }

    public function authorize(User $user, OAuthClient $client): bool
    {
        return $client->acceptsUser($user);
    }
}
