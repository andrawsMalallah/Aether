<?php

namespace App\Services\OAuth;

use App\Models\OAuthClient;
use Illuminate\Database\Eloquent\Collection;
use Laravel\Passport\Passport;

class RevokeClientCredentials
{
    // Call only inside the transaction holding the client's row lock, shared with issuance.
    public function handle(OAuthClient $client): void
    {
        Passport::authCode()->newQuery()->where('client_id', $client->id)->update(['revoked' => true]);
        Passport::token()->newQuery()->where('client_id', $client->id)->select('id')
            ->chunkById(500, function (Collection $tokens): void {
                $identifiers = $tokens->modelKeys();
                // Preserve refresh-before-access lock order and bounded ID batches.
                Passport::refreshToken()->newQuery()->whereIn('access_token_id', $identifiers)->update(['revoked' => true]);
                Passport::token()->newQuery()->whereIn('id', $identifiers)->update(['revoked' => true]);
            });
    }
}
