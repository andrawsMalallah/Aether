<?php

namespace App\Http\Controllers\OAuth;

use App\Actions\OAuth\CompleteConsent;
use App\Http\Requests\OAuth\ConsentRequest;
use Laravel\Passport\Http\Controllers\ConvertsPsrResponses;
use Laravel\Passport\Http\Controllers\HandlesOAuthErrors;
use Laravel\Passport\Http\Controllers\RetrievesAuthRequestFromSession;
use Psr\Http\Message\ResponseInterface;
use Symfony\Component\HttpFoundation\Response;

class ConsentController
{
    use ConvertsPsrResponses, HandlesOAuthErrors, RetrievesAuthRequestFromSession;

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
