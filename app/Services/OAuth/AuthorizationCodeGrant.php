<?php

namespace App\Services\OAuth;

use App\Models\OAuthClient;
use App\Models\User;
use Illuminate\Support\Facades\Gate;
use Laravel\Passport\Bridge\Client;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

class AuthorizationCodeGrant extends AuthCodeGrant
{
    protected function createAuthorizationRequest(): AuthorizationRequestInterface
    {
        return new OidcAuthorizationRequest;
    }

    public function validateAuthorizationRequest(ServerRequestInterface $request): AuthorizationRequestInterface
    {
        $parameters = $request->getQueryParams();
        // Aether requires PKCE for confidential clients too; the library verifies S256.
        if (($parameters['code_challenge_method'] ?? null) !== 'S256') {
            throw OAuthServerException::invalidRequest('code_challenge_method');
        }
        if (! isset($parameters['code_challenge'])) {
            throw OAuthServerException::invalidRequest('code_challenge');
        }
        if (! isset($parameters['redirect_uri'])) {
            throw OAuthServerException::invalidRequest('redirect_uri');
        }
        $authorization = parent::validateAuthorizationRequest($request);
        if ($authorization instanceof OidcAuthorizationRequest) {
            $authorization->nonce = $parameters['nonce'] ?? null;
        }
        $client = OAuthClient::query()->find($authorization->getClient()->getIdentifier());
        foreach ($authorization->getScopes() as $scope) {
            if (! $client?->hasScope($scope->getIdentifier()) || ! array_key_exists($scope->getIdentifier(), config('oauth.scopes'))) {
                throw OAuthServerException::invalidScope($scope->getIdentifier());
            }
        }

        return $authorization;
    }

    protected function validateRedirectUri(string $redirectUri, ClientEntityInterface $client, ServerRequestInterface $request): void
    {
        // League permits variable loopback ports; Aether's contract requires exact strings.
        if (! in_array($redirectUri, (array) $client->getRedirectUri(), true)) {
            throw OAuthServerException::invalidClient($request);
        }
    }

    public function completeAuthorizationRequest(AuthorizationRequestInterface $authorizationRequest): ResponseTypeInterface
    {
        $client = OAuthClient::query()->find($authorizationRequest->getClient()->getIdentifier());
        $user = User::query()->lockForUpdate()->find($authorizationRequest->getUser()?->getIdentifier());
        if (! $client || ! $user || Gate::forUser($user)->denies('authorize', $client)) {
            throw OAuthServerException::accessDenied();
        }
        $currentEntity = app(BridgeClientRepository::class)->getClientEntity($client->getKey());
        if (! $currentEntity instanceof Client || ! $currentEntity->supportsGrantType('authorization_code')) {
            throw OAuthServerException::unauthorizedClient();
        }
        if (! in_array($authorizationRequest->getRedirectUri(), $client->redirect_uris, true)) {
            throw OAuthServerException::invalidRequest('redirect_uri');
        }
        foreach ($authorizationRequest->getScopes() as $scope) {
            if (! $client->hasScope($scope->getIdentifier()) || ! array_key_exists($scope->getIdentifier(), config('oauth.scopes'))) {
                throw OAuthServerException::invalidScope($scope->getIdentifier());
            }
        }

        // Serialized authorization context survives login/consent, including automatic approval.
        $context = app(TokenContext::class);
        $context->authorization = $authorizationRequest instanceof OidcAuthorizationRequest ? $authorizationRequest : null;
        try {
            return parent::completeAuthorizationRequest($authorizationRequest);
        } finally {
            $context->authorization = null;
        }
    }
}
