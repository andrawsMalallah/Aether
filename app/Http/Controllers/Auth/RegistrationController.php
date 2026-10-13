<?php

namespace App\Http\Controllers\Auth;

use App\Actions\Auth\RegisterUser;
use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\RegisterRequest;
use Illuminate\Http\RedirectResponse;

class RegistrationController extends Controller
{
    public function store(RegisterRequest $request, RegisterUser $action): RedirectResponse
    {
        $action->handle($request->validated());

        return to_route('login')->with('status', 'If this address can be registered, a verification email will arrive. Sign in to continue, or reset your password if you already have an account.');
    }
}
