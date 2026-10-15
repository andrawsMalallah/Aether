<?php

namespace App\Http\Controllers\OAuth;

use App\Actions\OAuth\IntrospectToken;
use App\Http\Requests\OAuth\IntrospectTokenRequest;
use App\Http\Resources\OidcResource;
use Illuminate\Http\JsonResponse;
use Laravel\Passport\Http\Controllers\HandlesOAuthErrors;

class IntrospectTokenController
{
    use HandlesOAuthErrors;

    public function __invoke(IntrospectTokenRequest $request, IntrospectToken $action): JsonResponse
    {
        return $this->withErrorHandling(fn () => (new OidcResource($action->handle($request, $request->validated())))->response());
    }
}
