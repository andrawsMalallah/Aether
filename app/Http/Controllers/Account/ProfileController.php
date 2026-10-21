<?php

namespace App\Http\Controllers\Account;

use App\Actions\Account\ChangePassword;
use App\Actions\Account\ConfirmEmailChange;
use App\Actions\Account\RequestEmailChange;
use App\Actions\Account\UpdateProfile;
use App\Http\Controllers\Controller;
use App\Http\Requests\Account\ChangeEmailRequest;
use App\Http\Requests\Account\ChangePasswordRequest;
use App\Http\Requests\Account\UpdateProfileRequest;
use App\Models\User;
use App\Services\PrivateStorage;
use Illuminate\Contracts\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Symfony\Component\HttpFoundation\StreamedResponse;

class ProfileController extends Controller
{
    public function show(Request $request): View
    {
        Gate::authorize('view', $request->user());

        return view('account.profile', ['user' => $request->user()]);
    }

    public function update(UpdateProfileRequest $request, UpdateProfile $action): RedirectResponse
    {
        /** @var User $user */
        $user = $request->user();
        $action->handle($user, $request->validated());

        return to_route('account.profile')->with('status', 'Your profile has been updated.');
    }

    public function password(ChangePasswordRequest $request, ChangePassword $action): RedirectResponse
    {
        /** @var User $user */
        $user = $request->user();
        $action->handle($user, $request->validated('password'), $request->session()->getId());
        $request->session()->regenerate();

        return to_route('account.profile')->with('status', 'Your password has been changed. Other sessions have been signed out.');
    }

    public function email(ChangeEmailRequest $request, RequestEmailChange $action): RedirectResponse
    {
        /** @var User $user */
        $user = $request->user();
        $action->handle($user, $request->validated('email'));

        return to_route('account.profile')->with('status', 'A confirmation link has been sent to your new address. Your current address stays active until you confirm.');
    }

    public function verifyEmail(Request $request, User $user, string $hash, ConfirmEmailChange $action): RedirectResponse
    {
        Gate::authorize('update', $user);
        $action->handle($user, $hash);

        return to_route('account.profile')->with('status', 'Your new email address has been confirmed.');
    }

    public function avatar(Request $request): StreamedResponse
    {
        /** @var User $user */
        $user = $request->user();
        Gate::authorize('view', $user);
        abort_unless($user->avatar_path !== null && PrivateStorage::disk()->exists($user->avatar_path), 404);

        return PrivateStorage::response($user->avatar_path, PrivateStorage::disk()->mimeType($user->avatar_path) ?: 'application/octet-stream', ['Cache-Control' => 'private, no-store', 'X-Content-Type-Options' => 'nosniff']);
    }
}
