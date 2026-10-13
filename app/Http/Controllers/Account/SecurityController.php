<?php

namespace App\Http\Controllers\Account;

use App\Http\Controllers\Controller;
use App\Http\Requests\Account\ConfirmPasswordRequest;
use App\Http\Requests\Account\TwoFactorSettingsRequest;
use App\Models\User;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\ValidationException;
use Laravel\Fortify\Actions\ConfirmTwoFactorAuthentication;
use Laravel\Fortify\Actions\DisableTwoFactorAuthentication;
use Laravel\Fortify\Actions\EnableTwoFactorAuthentication;
use Laravel\Fortify\Actions\GenerateNewRecoveryCodes;

class SecurityController extends Controller
{
    public function show(Request $request): Response
    {
        Gate::authorize('view', $request->user());
        /** @var User $user */
        $user = $request->user();

        // Consume a display flag rather than copying recovery credentials into the session.
        $recoveryCodes = $request->session()->pull('show_recovery_codes', false) && $user->hasEnabledTwoFactorAuthentication()
            ? $user->recoveryCodes() : [];

        return response()->view('account.security', compact('user', 'recoveryCodes'))
            ->header('Cache-Control', 'no-store, private');
    }

    public function passwordForm(Request $request): Response
    {
        Gate::authorize('view', $request->user());

        return response()->view('auth.confirm-password')->header('Cache-Control', 'no-store, private');
    }

    public function confirmPassword(ConfirmPasswordRequest $request): RedirectResponse
    {
        $request->session()->put('auth.password_confirmed_at', now()->timestamp);

        return redirect()->intended(route('account.security'));
    }

    public function enable(TwoFactorSettingsRequest $request, EnableTwoFactorAuthentication $enable): RedirectResponse
    {
        $enable($request->user());

        return to_route('account.security')->with('status', 'Scan the QR code, then enter a code to finish setup.');
    }

    public function confirm(TwoFactorSettingsRequest $request, ConfirmTwoFactorAuthentication $confirm): RedirectResponse
    {
        /** @var User $user */
        $user = $request->user();
        abort_if($user->hasEnabledTwoFactorAuthentication(), 409);
        try {
            $confirm($user, $request->validated('code'));
        } catch (ValidationException $exception) {
            // Our shared field components use the default error bag.
            throw $exception->errorBag('default')->redirectTo(route('account.security'));
        }

        return to_route('account.security')->with('show_recovery_codes', true)->with('status', 'Two-factor authentication is enabled. Save your recovery codes.');
    }

    public function regenerate(TwoFactorSettingsRequest $request, GenerateNewRecoveryCodes $generate): RedirectResponse
    {
        /** @var User $user */
        $user = $request->user();
        abort_unless($user->hasEnabledTwoFactorAuthentication(), 409);
        $generate($user);

        return to_route('account.security')->with('show_recovery_codes', true)->with('status', 'New recovery codes generated. Your previous codes no longer work.');
    }

    public function disable(TwoFactorSettingsRequest $request, DisableTwoFactorAuthentication $disable): RedirectResponse
    {
        $disable($request->user());
        $request->session()->forget('show_recovery_codes');

        return to_route('account.security')->with('status', 'Two-factor authentication is disabled.');
    }
}
