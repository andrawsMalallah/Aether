<?php

namespace App\Http\Middleware;

use App\Models\User;
use App\Services\AccountDeletionAccess;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class RestrictDeletingAccount
{
    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();
        if (! $user instanceof User) {
            return $next($request);
        }
        // Re-read instead of trusting a user loaded before a concurrent deletion request.
        $user = $user->fresh();
        if ($user?->accountAvailable()) {
            return $next($request);
        }
        if ($request->routeIs('logout')) {
            return $next($request);
        }
        if ($user && app(AccountDeletionAccess::class)->recentlyAuthenticated($request, $user)) {
            if ($request->routeIs('account.deletion.pending', 'account.deletion.cancel')) {
                return $next($request)->header('Cache-Control', 'no-store, private');
            }

            return to_route('account.deletion.pending')->header('Cache-Control', 'no-store, private');
        }
        Auth::guard('web')->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return to_route('login')->with('status', 'Sign in again to review your account deletion request.')->header('Cache-Control', 'no-store, private');
    }
}
