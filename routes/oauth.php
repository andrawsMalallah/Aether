<?php

use App\Http\Controllers\OAuth\AuthorizationController;
use App\Http\Controllers\OAuth\ClientLogoController;
use App\Http\Controllers\OAuth\ConsentController;
use App\Http\Controllers\OAuth\OidcMetadataController;
use App\Http\Controllers\OAuth\RevokeTokenController;
use App\Http\Controllers\OAuth\TokenController;
use App\Http\Controllers\OAuth\UserInfoController;
use App\Http\Middleware\OAuthResponse;
use Illuminate\Support\Facades\Route;

Route::middleware(OAuthResponse::class)->group(function (): void {
    Route::get('/.well-known/openid-configuration', [OidcMetadataController::class, 'discovery'])->name('oidc.discovery');
    Route::get('/.well-known/jwks.json', [OidcMetadataController::class, 'keys'])->name('oidc.jwks');
});

Route::prefix('oauth')->name('passport.')->middleware(OAuthResponse::class)->group(function (): void {
    // Back-channel protocol endpoints deliberately have no browser session or CSRF middleware.
    Route::post('/token', [TokenController::class, 'store'])->middleware('throttle:oauth-token')->name('token');
    Route::post('/revoke', RevokeTokenController::class)->middleware('throttle:oauth-revoke')->name('revoke');
    Route::match(['GET', 'POST'], '/userinfo', UserInfoController::class)->middleware('throttle:oidc-userinfo')->name('userinfo');
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
