<?php

use App\Http\Controllers\OAuth\AuthorizationController;
use App\Http\Controllers\OAuth\ClientLogoController;
use App\Http\Controllers\OAuth\ConsentController;
use App\Http\Controllers\OAuth\RevokeTokenController;
use App\Http\Controllers\OAuth\TokenController;
use App\Http\Middleware\OAuthResponse;
use Illuminate\Support\Facades\Route;

Route::prefix('oauth')->name('passport.')->middleware(OAuthResponse::class)->group(function (): void {
    // Back-channel protocol endpoints deliberately have no browser session or CSRF middleware.
    Route::post('/token', [TokenController::class, 'store'])->middleware('throttle:oauth-token')->name('token');
    Route::post('/revoke', RevokeTokenController::class)->middleware('throttle:oauth-revoke')->name('revoke');
    Route::middleware(['web', 'throttle:oauth-authorize'])->group(function (): void {
        // Passport validates the redirect before it prompts a guest to sign in.
        Route::get('/authorize', [AuthorizationController::class, 'authorize'])->name('authorizations.authorize');
        Route::middleware(['auth', 'verified'])->group(function (): void {
            Route::get('/clients/{client}/logo', ClientLogoController::class)->name('client.logo');
            Route::post('/authorize', [ConsentController::class, 'approve'])->name('authorizations.approve');
            Route::delete('/authorize', [ConsentController::class, 'deny'])->name('authorizations.deny');
        });
    });
});
