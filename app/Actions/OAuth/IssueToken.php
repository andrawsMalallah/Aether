<?php

namespace App\Actions\OAuth;

use App\Enums\OAuthAuditEvent;
use App\Models\AuditLog;
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
                $result = app(AuthorizationServer::class)->respondToAccessTokenRequest($request, $response);
                $owner = app(TokenContext::class)->issuedCredentialOwner;
                if ($result->getStatusCode() === 200 && $owner !== null) {
                    $body = $request->getParsedBody();
                    $refresh = is_array($body) && ($body['grant_type'] ?? null) === 'refresh_token';
                    AuditLog::create([...$owner, 'event' => $refresh ? OAuthAuditEvent::TokenRefreshed : OAuthAuditEvent::TokenIssued]);
                }

                return $result;
            } catch (OAuthServerException $exception) {
                // Commit replay revocations/audit events even when the exchange is rejected.
                return $exception->generateHttpResponse($response);
            }
        });
    }
}
