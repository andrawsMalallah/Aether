<?php

namespace App\Http\Controllers\OAuth;

use App\Actions\OAuth\ReadUserInfo;
use App\Http\Controllers\Controller;
use App\Http\Resources\OidcResource;
use Illuminate\Http\JsonResponse;
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ServerRequestInterface;

class UserInfoController extends Controller
{
    public function __invoke(ServerRequestInterface $request, ReadUserInfo $action): OidcResource|JsonResponse
    {
        try {
            return new OidcResource($action->handle($request));
        } catch (OAuthServerException $exception) {
            $insufficientScope = $exception->getErrorType() === 'invalid_scope';

            return response()->json(['error' => $insufficientScope ? 'insufficient_scope' : 'invalid_token'], $insufficientScope ? 403 : 401,
                ['WWW-Authenticate' => $insufficientScope ? 'Bearer error="insufficient_scope", scope="openid"' : 'Bearer error="invalid_token"']);
        }
    }
}
