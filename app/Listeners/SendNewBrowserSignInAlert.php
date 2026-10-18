<?php

namespace App\Listeners;

use App\Models\User;
use App\Notifications\NewBrowserSignIn;
use App\Services\BrowserDescription;
use Illuminate\Auth\Events\Login;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;

class SendNewBrowserSignInAlert
{
    public function handle(Login $event): void
    {
        $request = request();
        // Ignore remembered-session restoration and programmatic logins. Fortify emits
        // Login only after the required password and second-factor checks succeed.
        if ($event->guard !== 'web' || ! $event->user instanceof User
            || ! $request->isMethod('POST') || ! $request->routeIs('login.store', 'two-factor.login.store')
            || Auth::guard('web')->viaRemember()) {
            return;
        }

        // EncryptCookies authenticates both this value and its account-specific name.
        // This cookie is only an alert marker; it never grants authentication or 2FA trust.
        $name = 'aether_browser_'.hash('sha256', (string) $event->user->getAuthIdentifier());
        $expires = $request->cookie($name);
        $now = now()->timestamp;
        $retention = 90 * 24 * 60;
        if (is_string($expires) && ctype_digit($expires)
            && (int) $expires > $now && (int) $expires <= $now + $retention * 60) {
            return;
        }

        $event->user->notify(new NewBrowserSignIn(
            app(BrowserDescription::class)->describe($request->userAgent() ?? ''),
            $request->ip() ?? 'Unavailable',
            now()->utc()->format('Y-m-d H:i:s').' UTC',
        ));

        // Fixed expiry: ordinary visits and recognized sign-ins do not extend retention.
        Cookie::queue(Cookie::make($name, (string) ($now + $retention * 60), $retention,
            '/', null, true, true, false, 'lax'));
    }
}
