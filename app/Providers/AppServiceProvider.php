<?php

namespace App\Providers;

use Illuminate\Support\Facades\Vite;
use Illuminate\Support\ServiceProvider;
use Illuminate\Validation\Rules\Password;
use Laravel\Fortify\Fortify;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        // Explicit routes keep Form Requests and enumeration-safe responses under our control.
        Fortify::ignoreRoutes();
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // The enforced same-origin CSP uses built assets in every environment.
        // An empty hot-file path ignores dev-server markers without deleting them.
        Vite::useHotFile('');
        Password::defaults(fn (): Password => Password::min(8)->uncompromised());
    }
}
