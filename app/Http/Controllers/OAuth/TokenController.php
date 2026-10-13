<?php

namespace App\Http\Controllers\OAuth;

use App\Actions\OAuth\IssueToken;
use App\Http\Requests\OAuth\TokenRequest;
use Laravel\Passport\Http\Controllers\ConvertsPsrResponses;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\HttpFoundation\Response;

class TokenController
{
    use ConvertsPsrResponses;

    public function store(TokenRequest $request, ServerRequestInterface $psrRequest, ResponseInterface $response, IssueToken $action): Response
    {
        return $this->convertResponse($action->handle($psrRequest, $response));
    }
}
