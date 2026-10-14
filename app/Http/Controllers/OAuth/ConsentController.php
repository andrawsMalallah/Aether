<?php

namespace App\Http\Controllers\OAuth;

use App\Actions\OAuth\CompleteConsent;
use App\Http\Requests\OAuth\ConsentRequest;
use App\Services\OAuth\OidcAuthorizationRequest;
use Illuminate\Http\Request;
use Laravel\Passport\Bridge\Client;
use Laravel\Passport\Bridge\Scope;
use Laravel\Passport\Bridge\User;
use Laravel\Passport\Exceptions\InvalidAuthTokenException;
use Laravel\Passport\Http\Controllers\ConvertsPsrResponses;
use Laravel\Passport\Http\Controllers\HandlesOAuthErrors;
use League\OAuth2\Server\RequestTypes\AuthorizationRequest;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Symfony\Component\HttpFoundation\Response;

class ConsentController
{
    use ConvertsPsrResponses, HandlesOAuthErrors;

    protected function getAuthRequestFromSession(Request $request): AuthorizationRequestInterface
    {
        if ($request->isNotFilled('auth_token') || $request->session()->pull('authToken') !== $request->input('auth_token')) {
            $request->session()->forget(['authToken', 'authRequest']);
            throw InvalidAuthTokenException::different();
        }
        $serialized = $request->session()->pull('authRequest');
        if (! is_string($serialized)) {
            throw InvalidAuthTokenException::different();
        }
        // Preserve Passport's strict allowlist, adding only our inert context-bearing request.
        $authorization = unserialize($serialized, ['allowed_classes' => [
            OidcAuthorizationRequest::class,
            AuthorizationRequest::class,
            Client::class,
            Scope::class,
            User::class,
        ]]);
        if (! $authorization instanceof AuthorizationRequestInterface) {
            throw InvalidAuthTokenException::different();
        }

        return $authorization;
    }

    public function approve(ConsentRequest $request, ResponseInterface $response, CompleteConsent $action): Response
    {
        return $this->complete($request, $response, $action, true);
    }

    public function deny(ConsentRequest $request, ResponseInterface $response, CompleteConsent $action): Response
    {
        return $this->complete($request, $response, $action, false);
    }

    private function complete(ConsentRequest $request, ResponseInterface $response, CompleteConsent $action, bool $approved): Response
    {
        $authorization = $this->getAuthRequestFromSession($request);

        return $this->withErrorHandling(fn () => $this->convertResponse($action->handle($authorization, $request->user(), $approved, $response)));
    }
}
