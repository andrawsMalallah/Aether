<?php

namespace App\Actions\OAuth;

use App\Models\User;
use App\Services\OAuth\IdentityClaims;
use Illuminate\Support\Facades\Gate;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResourceServer;
use Psr\Http\Message\ServerRequestInterface;

class ReadUserInfo
{
    /** @return array<string, string|bool> */
    public function handle(ServerRequestInterface $request): array
    {
        // Validate a bearer credential directly: session/cookie auth cannot authorize userinfo.
        $authenticated = app(ResourceServer::class)->validateAuthenticatedRequest($request);
        $userId = $authenticated->getAttribute('oauth_user_id');
        $scopes = $authenticated->getAttribute('oauth_scopes', []);
        if (! $userId || ! in_array('openid', $scopes, true)) {
            throw OAuthServerException::invalidScope('openid');
        }
        // Machine tokens can carry their client UUID as subject; it is never a user ID.
        if ((! is_string($userId) && ! is_int($userId))
            || filter_var($userId, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]) === false) {
            throw OAuthServerException::accessDenied();
        }
        $user = User::query()->find($userId);
        if (! $user) {
            throw OAuthServerException::accessDenied();
        }
        Gate::forUser($user)->authorize('view', $user);

        return app(IdentityClaims::class)->forUser($user, $scopes);
    }
}
