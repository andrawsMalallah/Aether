<?php

namespace App\Services\OAuth;

use App\Models\User;
use Laravel\Passport\Passport;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\ResponseTypes\BearerTokenResponse;
use RuntimeException;

class OidcTokenResponse extends BearerTokenResponse
{
    /** @return array<string, mixed> */
    protected function getExtraParams(AccessTokenEntityInterface $accessToken): array
    {
        $scopes = array_map(fn ($scope): string => $scope->getIdentifier(), $accessToken->getScopes());
        $parameters = ['scope' => implode(' ', $scopes)];
        if ($accessToken->getUserIdentifier() === null || ! in_array('openid', $scopes, true)) {
            return $parameters;
        }
        $issuedToken = Passport::token()->newQuery()->find($accessToken->getIdentifier());
        if (! $issuedToken || $issuedToken->oidc_auth_time === null || $issuedToken->client_id !== $accessToken->getClient()->getIdentifier()
            || (string) $issuedToken->user_id !== $accessToken->getUserIdentifier()) {
            throw new RuntimeException('OIDC authorization context is unavailable.');
        }
        $user = User::query()->findOrFail($accessToken->getUserIdentifier());
        $keys = app(OidcKeys::class);
        $configuration = Configuration::forAsymmetricSigner(new Sha256, $keys->privateKey(), $keys->publicKey());
        $issuedAt = now()->toDateTimeImmutable();
        $builder = $configuration->builder()->issuedBy(app(OidcMetadata::class)->issuer())
            ->permittedFor($issuedToken->client_id)->relatedTo((string) $user->getKey())
            ->issuedAt($issuedAt)->expiresAt($issuedAt->modify('+'.(int) config('oidc.id_token_lifetime').' seconds'))
            ->withHeader('kid', $keys->jwk()['kid'])->withClaim('auth_time', (int) $issuedToken->oidc_auth_time);
        // On refresh, preserve the original nonce/auth_time, never take them from the token request.
        if ($issuedToken->oidc_nonce !== null) {
            $builder = $builder->withClaim('nonce', $issuedToken->oidc_nonce);
        }
        foreach (app(IdentityClaims::class)->forUser($user, $scopes) as $claim => $value) {
            if ($claim !== 'sub') {
                $builder = $builder->withClaim($claim, $value);
            }
        }

        return [...$parameters, 'id_token' => $builder->getToken($configuration->signer(), $configuration->signingKey())->toString()];
    }
}
