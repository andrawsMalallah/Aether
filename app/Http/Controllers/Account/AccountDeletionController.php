<?php

namespace App\Http\Controllers\Account;

use App\Actions\Account\CancelAccountDeletion;
use App\Actions\Account\RequestAccountDeletion;
use App\Http\Controllers\Controller;
use App\Http\Requests\Account\CancelAccountDeletionRequest;
use App\Http\Requests\Account\RequestAccountDeletionRequest;
use App\Http\Resources\AccountDeletionResource;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Gate;

class AccountDeletionController extends Controller
{
    public function show(Request $request): Response
    {
        Gate::authorize('view', $request->user());

        return response()->view('account.deletion', ['administrator' => $request->user()->is_admin])->header('Cache-Control', 'no-store, private');
    }

    public function store(RequestAccountDeletionRequest $request, RequestAccountDeletion $action): RedirectResponse
    {
        $action->handle($request->user());

        return $this->signOut($request, 'Deletion requested. Sign in before the 14-day deadline if you want to cancel.');
    }

    public function pending(Request $request): Response
    {
        Gate::authorize('cancelDeletion', $request->user());

        return response()->view('account.deletion-pending', ['deletion' => (new AccountDeletionResource($request->user()))->resolve($request)])
            ->header('Cache-Control', 'no-store, private');
    }

    public function cancel(CancelAccountDeletionRequest $request, CancelAccountDeletion $action): RedirectResponse
    {
        $action->handle($request);

        return $this->signOut($request, 'Account deletion cancelled. Sign in again to use your account. Previous sessions and application approvals stay revoked.');
    }

    private function signOut(Request $request, string $status): RedirectResponse
    {
        Auth::guard('web')->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return to_route('login')->with('status', $status)->header('Cache-Control', 'no-store, private');
    }
}
