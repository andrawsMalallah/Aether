<?php

namespace App\Services\OAuth;

use App\Models\OAuthClient;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository as PassportClientRepository;

class ClientRepository extends PassportClientRepository
{
    public function find(string|int $id): ?Client
    {
        // Do not retain a cached client across exchanges in a long-lived worker.
        return OAuthClient::query()->find($id);
    }

    public function findActive(string|int $id): ?Client
    {
        $client = OAuthClient::query()->find($id);

        return $client?->available() ? $client : null;
    }
}
