<?php

namespace App\Http\Controllers\Auth;

use App\Actions\Auth\ResetUserPassword;
use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\ForgotPasswordRequest;
use App\Http\Requests\Auth\ResetPasswordRequest;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Password;
use Illuminate\Validation\ValidationException;

class PasswordResetController extends Controller
{
    public function request(ForgotPasswordRequest $request): RedirectResponse
    {
        Password::broker()->sendResetLink($request->validated());

        return back()->with('status', 'If an account matches this address, a password reset link will arrive shortly.');
    }

    public function reset(ResetPasswordRequest $request, ResetUserPassword $action): RedirectResponse
    {
        $status = $action->handle($request->validated());
        if ($status !== Password::PasswordReset) {
            throw ValidationException::withMessages(['email' => 'This reset link is invalid or has expired. Request a new link.']);
        }

        return to_route('login')->with('status', 'Your password has been reset. Sign in with your new password.');
    }
}
