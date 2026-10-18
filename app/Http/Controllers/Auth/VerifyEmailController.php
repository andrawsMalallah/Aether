<?php

namespace App\Http\Controllers\Auth;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Laravel\Fortify\Contracts\VerifyEmailResponse;
use Laravel\Fortify\Http\Controllers\VerifyEmailController as FortifyVerifyEmailController;
use Laravel\Fortify\Http\Requests\VerifyEmailRequest;

class VerifyEmailController extends FortifyVerifyEmailController
{
    public function __invoke(VerifyEmailRequest $request): VerifyEmailResponse
    {
        Gate::authorize('update', $request->user());

        // Preserve Fortify's validation/event/response while committing its audit atomically.
        return DB::transaction(fn () => parent::__invoke($request));
    }
}
