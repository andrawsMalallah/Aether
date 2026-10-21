<?php

namespace App\Services\OAuth;

use App\Models\OAuthClient;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository as PassportClientRepository;

class ClientRepository extends PassportClientRepository
{
    public function find(string|int $id): ?Client
    {
        if (! Str::isUuid((string) $id)) {
            return null;
        }

        // Do not retain a cached client across exchanges in a long-lived worker.
        return OAuthClient::query()->find($id);
    }

    public function findActive(string|int $id): ?Client
    {
        if (! Str::isUuid((string) $id)) {
            return null;
        }
        $query = OAuthClient::query();
        // Exchanges and developer changes share this lock, preventing issuance across rotation.
        if (DB::transactionLevel() > 0) {
            $query->lockForUpdate();
        }
        $client = $query->find($id);

        return $client?->available() ? $client : null;
    }
}
