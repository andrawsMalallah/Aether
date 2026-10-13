<?php

namespace App\Http\Controllers\OAuth;

use App\Http\Requests\OAuth\AuthorizeRequest;
use App\Models\Consent;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Laravel\Passport\Client;
use Laravel\Passport\Contracts\AuthorizationViewResponse;
use Laravel\Passport\Http\Controllers\AuthorizationController as PassportAuthorizationController;
use Laravel\Passport\Scope;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\HttpFoundation\Response;

class AuthorizationController extends PassportAuthorizationController
{
    public function authorize(ServerRequestInterface $psrRequest, Request $request, ResponseInterface $psrResponse, AuthorizationViewResponse $viewResponse): Response|AuthorizationViewResponse
    {
        // A stale consent form must not survive a new authorization request.
        $request->session()->forget(['authToken', 'authRequest']);
        app(AuthorizeRequest::class);

        return parent::authorize($psrRequest, $request, $psrResponse, $viewResponse);
    }

    /** @return Scope[] */
    protected function parseScopes(AuthorizationRequestInterface $authRequest): array
    {
        Gate::forUser($this->guard->user())->authorize('authorize', $this->clients->find($authRequest->getClient()->getIdentifier()));

        return parent::parseScopes($authRequest);
    }

    /** @param Scope[] $scopes */
    protected function hasGrantedScopes(Authenticatable $user, Client $client, array $scopes): bool
    {
        // Consent survives token expiry, but an explicit user revocation always wins.
        $consent = Consent::query()->where('user_id', $user->getAuthIdentifier())
            ->where('client_id', $client->getKey())->whereNull('revoked_at')->first();

        return $consent && ! array_diff(array_map(fn ($scope): string => $scope->id, $scopes), $consent->scopes);
    }
}
