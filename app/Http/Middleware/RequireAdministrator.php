<?php

namespace App\Http\Middleware;

use App\Models\User;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class RequireAdministrator
{
    public function handle(Request $request, Closure $next): Response
    {
        /** @var User|null $user */
        $user = $request->user();
        abort_unless($user?->is_admin && $user->hasVerifiedEmail(), 403);
        if (! $user->hasEnabledTwoFactorAuthentication()) {
            return to_route('account.security')->with('status', 'Enable and confirm two-factor authentication before opening administration.')
                ->header('Cache-Control', 'private, no-store');
        }

        return $next($request)->header('Cache-Control', 'private, no-store');
    }
}
