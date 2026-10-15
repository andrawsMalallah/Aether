<?php

namespace App\Actions\OAuth;

use App\Enums\OAuthAppType;
use App\Enums\OAuthClientStatus;
use App\Models\OAuthClient;
use App\Services\OAuth\OidcMetadata;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Hash;
use Laravel\Passport\Passport;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResourceServer;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;

class IntrospectToken
{
    /** @param array<string, mixed> $data
     * @return array<string, bool|string|int>
     */
    public function handle(Request $request, array $data): array
    {
        $clientId = $data['client_id'] ?? $request->getUser();
        $secret = $data['client_secret'] ?? $request->getPassword();
        $resource = is_string($clientId) ? OAuthClient::query()->find($clientId) : null;
        if (! $resource || ! $resource->confidential() || ! is_string($secret)
            || ! is_string($resource->secret) || ! Hash::check($secret, $resource->secret)) {
            throw OAuthServerException::invalidClient((new PsrHttpFactory)->createRequest($request));
        }
        if (! Gate::allows('introspectToken', $resource)) {
            throw OAuthServerException::accessDenied();
        }

        // Reuse the real bearer validator and revocation repository; never trust a decoded JWT alone.
        $bearer = (new PsrHttpFactory)->createRequest(Request::create('/resource', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$data['token']]));
        try {
            $validated = app(ResourceServer::class)->validateAuthenticatedRequest($bearer);
        } catch (OAuthServerException) {
            return ['active' => false];
        }
        $token = Passport::token()->newQuery()->find($validated->getAttribute('oauth_access_token_id'));
        $machine = $token ? OAuthClient::query()->find($token->client_id) : null;
        if (! $token || $token->user_id !== null || $token->revoked || $token->expires_at->isPast()
            || ! $machine || $machine->status !== OAuthClientStatus::Live || ! $machine->available()
            || ! $machine->confidential() || $machine->app_type !== OAuthAppType::Machine
            || ! in_array('client_credentials', $machine->grant_types, true)
            || ! in_array($machine->getKey(), $resource->introspection_client_ids ?? [], true)
            || array_diff($token->scopes, $machine->allowed_scopes ?? [])) {
            // Hide metadata for tokens the authenticated resource is not authorized to inspect.
            return ['active' => false];
        }

        return [
            'active' => true,
            'client_id' => $machine->getKey(),
            'client_type' => $machine->app_type->value,
            'grant_type' => 'client_credentials',
            'resource_client_id' => $resource->getKey(),
            'scope' => implode(' ', $token->scopes),
            'token_type' => 'Bearer',
            'exp' => $token->expires_at->timestamp,
            'iss' => app(OidcMetadata::class)->issuer(),
        ];
    }
}
