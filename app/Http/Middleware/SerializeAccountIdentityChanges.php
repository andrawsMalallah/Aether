<?php

namespace App\Http\Middleware;

use App\Models\User;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Symfony\Component\HttpFoundation\Response;

class SerializeAccountIdentityChanges
{
    public function handle(Request $request, Closure $next): Response
    {
        $query = User::query();
        if ($request->isMethod('POST') && $request->routeIs('login.store')) {
            $email = $request->input('email');
            if (! is_string($email)) {
                return $next($request);
            }
            $query->where('email', strtolower($email));
        } elseif ($request->isMethod('POST') && $request->routeIs('two-factor.login.store')) {
            $identifier = $request->session()->get('login.id');
            if (! is_int($identifier) && ! is_string($identifier)) {
                return $next($request);
            }
            $query->whereKey($identifier);
        } elseif ($request->routeIs('account.profile.update', 'account.password.update', 'account.email.update', 'account.email.verify',
            'account.two-factor.*', 'account.developer.enable') && $request->user() instanceof User) {
            $query->whereKey($request->user()->getAuthIdentifier());
        } else {
            return $next($request);
        }

        return DB::transaction(function () use ($query, $request, $next): Response {
            $user = $query->lockForUpdate()->first();
            if ($user !== null && ! $user->accountAvailable()) {
                // Only the normal complete password/2FA flow can establish cancellation access.
                abort_unless($request->routeIs('login.store', 'two-factor.login.store') && $user->deletionCancellable(), 403);
                if ($request->routeIs('two-factor.login.store')) {
                    $proof = $request->session()->get('deletion.password');
                    abort_unless(is_array($proof) && ($proof['requested_at'] ?? null) === $user->deletion_requested_at?->toISOString()
                        && is_int($proof['time'] ?? null) && $proof['time'] > now()->subMinutes(5)->timestamp, 403);
                }
            }
            if ($user !== null && $request->user() instanceof User) {
                Auth::guard('web')->setUser($user);
            }

            return $next($request);
        });
    }
}
