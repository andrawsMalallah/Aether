<?php

namespace App\Services\OAuth;

use League\OAuth2\Server\AuthorizationValidators\AuthorizationValidatorInterface;
use League\OAuth2\Server\AuthorizationValidators\BearerTokenValidator;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use Psr\Http\Message\ServerRequestInterface;

class TrustedBearerTokenValidator implements AuthorizationValidatorInterface
{
    public function __construct(private AccessTokenRepositoryInterface $repository, private OidcKeys $keys) {}

    public function validateAuthorization(ServerRequestInterface $request): ServerRequestInterface
    {
        // Existing Passport JWTs have no kid. Try only this bounded trusted ring;
        // every attempt retains League's time, signature and repository checks.
        foreach ($this->keys->publicKeys() as $pem) {
            $validator = new BearerTokenValidator($this->repository);
            $validator->setPublicKey(new CryptKey($pem, null, false));
            try {
                return $validator->validateAuthorization($request);
            } catch (OAuthServerException) {
                // Another trusted overlap key may have signed this token.
            }
        }

        throw OAuthServerException::accessDenied('Access token could not be verified');
    }
}
