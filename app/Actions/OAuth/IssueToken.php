<?php

namespace App\Actions\OAuth;

use App\Services\OAuth\TokenContext;
use Illuminate\Support\Facades\DB;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class IssueToken
{
    public function handle(ServerRequestInterface $request, ResponseInterface $response): ResponseInterface
    {
        app(TokenContext::class)->reset();

        return DB::transaction(function () use ($request, $response): ResponseInterface {
            try {
                return app(AuthorizationServer::class)->respondToAccessTokenRequest($request, $response);
            } catch (OAuthServerException $exception) {
                // Commit replay revocations/audit events even when the exchange is rejected.
                return $exception->generateHttpResponse($response);
            }
        });
    }
}
