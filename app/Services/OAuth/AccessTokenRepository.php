<?php

namespace App\Services\OAuth;

use App\Enums\OAuthClientStatus;
use App\Models\OAuthClient;
use App\Models\User;
use Laravel\Passport\Bridge\AccessTokenRepository as PassportAccessTokenRepository;
use Laravel\Passport\Passport;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;

class AccessTokenRepository extends PassportAccessTokenRepository
{
    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        parent::persistNewAccessToken($accessTokenEntity);
        $context = app(TokenContext::class);
        Passport::token()->newQuery()->whereKey($accessTokenEntity->getIdentifier())
            ->update(['auth_code_id' => $context->authCodeId, 'oidc_auth_time' => $context->authTime, 'oidc_nonce' => $context->nonce]);
        // Hold only safe references; issuance can still fail after persistence.
        $context->issuedCredentialOwner = ['user_id' => $accessTokenEntity->getUserIdentifier(), 'client_id' => $accessTokenEntity->getClient()->getIdentifier()];
    }

    public function isAccessTokenRevoked(string $tokenId): bool
    {
        $token = Passport::token()->newQuery()->find($tokenId);
        if (! $token || $token->revoked) {
            return true;
        }
        $client = OAuthClient::query()->find($token->client_id);
        if (! $client?->available() || array_diff($token->scopes, $client->allowed_scopes ?? [])) {
            return true;
        }

        return $token->user_id !== null
            ? ! (($user = User::query()->find($token->user_id)) && $client->acceptsUser($user))
            : $client->status !== OAuthClientStatus::Live;
    }
}
