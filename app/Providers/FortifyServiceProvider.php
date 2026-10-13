<?php

namespace App\Providers;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\View\View;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Laravel\Fortify\Fortify;

class FortifyServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        Fortify::loginView(fn (): View => view('auth.login'));
        Fortify::verifyEmailView(fn (): View => view('auth.verify-email'));
        RateLimiter::for('login', function (Request $request): array {
            $email = is_string($request->input('email')) ? strtolower($request->input('email')) : '';

            return [
                Limit::perMinute(5)->by('login:email:'.$email.':'.$request->ip()),
                Limit::perMinute(30)->by('login:ip:'.$request->ip()),
            ];
        });
        RateLimiter::for('registration', fn (Request $request): Limit => Limit::perHour(10)->by('registration:'.$request->ip()));
        RateLimiter::for('forgot-password', function (Request $request): array {
            $email = is_string($request->input('email')) ? strtolower($request->input('email')) : '';

            return [
                Limit::perHour(3)->by('forgot-password:email:'.$email),
                Limit::perHour(10)->by('forgot-password:ip:'.$request->ip()),
            ];
        });
        RateLimiter::for('reset-password', fn (Request $request): Limit => Limit::perMinute(5)->by('reset-password:'.$request->ip()));
        RateLimiter::for('verification', fn (Request $request): Limit => Limit::perHour(6)->by('verification:'.$request->user()?->getAuthIdentifier()));
        RateLimiter::for('account-changes', fn (Request $request): Limit => Limit::perMinute(10)->by('account-changes:'.$request->user()?->getAuthIdentifier()));
    }
}
