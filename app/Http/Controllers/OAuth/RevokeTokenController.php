<?php

namespace App\Http\Controllers\OAuth;

use App\Actions\OAuth\RevokeToken;
use App\Http\Requests\OAuth\RevokeTokenRequest;
use Laravel\Passport\Http\Controllers\HandlesOAuthErrors;
use Symfony\Component\HttpFoundation\Response;

class RevokeTokenController
{
    use HandlesOAuthErrors;

    public function __invoke(RevokeTokenRequest $request, RevokeToken $action): Response
    {
        $this->withErrorHandling(fn () => $action->handle($request, $request->validated()));

        // RFC 7009 requires an empty successful response, also for unknown tokens.
        return response('', 200);
    }
}
