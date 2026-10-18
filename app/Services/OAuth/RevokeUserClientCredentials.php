<?php

namespace App\Services\OAuth;

use App\Models\OAuthClient;
use App\Models\User;
use Illuminate\Database\Eloquent\Collection;
use Laravel\Passport\Passport;

class RevokeUserClientCredentials
{
    // The caller holds the shared client lock inside a transaction, matching issuance.
    public function handle(User $user, OAuthClient $client): void
    {
        Passport::authCode()->newQuery()->where('client_id', $client->id)->where('user_id', $user->id)->update(['revoked' => true]);
        Passport::token()->newQuery()->where('client_id', $client->id)->where('user_id', $user->id)->select('id')
            ->chunkById(500, function (Collection $tokens): void {
                $identifiers = $tokens->modelKeys();
                // Match refresh-before-access locking without touching other users' grants.
                Passport::refreshToken()->newQuery()->whereIn('access_token_id', $identifiers)->update(['revoked' => true]);
                Passport::token()->newQuery()->whereIn('id', $identifiers)->update(['revoked' => true]);
            });
    }
}
