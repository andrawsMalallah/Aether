<?php

namespace App\Listeners;

use App\Models\User;
use Illuminate\Auth\Events\Login;
use Illuminate\Support\Facades\Auth;
use Laravel\Fortify\Events\TwoFactorAuthenticationChallenged;

class RecognizeDeletionCancellationLogin
{
    public function handleChallenge(TwoFactorAuthenticationChallenged $event): void
    {
        $request = request();
        if (! $request->hasSession() || ! $request->isMethod('POST') || ! $request->routeIs('login.store')) {
            return;
        }
        $user = $event->user->fresh();
        if ($user?->deletionCancellable()) {
            $request->session()->put('deletion.password', [
                'requested_at' => $user->deletion_requested_at?->toISOString(), 'time' => now()->timestamp,
            ]);
        }
    }

    public function handle(Login $event): void
    {
        $request = request();
        if ($event->guard !== 'web' || ! $event->user instanceof User || Auth::guard('web')->viaRemember()
            || ! $request->hasSession() || ! $request->isMethod('POST')
            || ! $request->routeIs('login.store', 'two-factor.login.store')) {
            return;
        }
        $user = $event->user->fresh();
        if ($user?->deletionCancellable()) {
            $request->session()->put('deletion.login', [
                'user_id' => (string) $user->id,
                'requested_at' => $user->deletion_requested_at?->toISOString(),
                'time' => now()->timestamp,
            ]);
            // Discard stale OAuth/intended destinations; only cancellation is available.
            $request->session()->put('url.intended', route('account.deletion.pending'));
        }
    }
}
