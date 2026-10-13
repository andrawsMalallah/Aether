<?php

namespace App\Policies;

use App\Models\OAuthClient;
use App\Models\User;

class OAuthClientPolicy
{
    public function revokeToken(?User $user, OAuthClient $client, string $authenticatedClientId): bool
    {
        return $client->getKey() === $authenticatedClientId;
    }

    public function authorize(User $user, OAuthClient $client): bool
    {
        return $client->acceptsUser($user);
    }
}
