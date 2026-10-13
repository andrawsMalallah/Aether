<?php

use App\Http\Controllers\Account\ProfileController;
use App\Http\Controllers\Account\SecurityController;
use App\Http\Controllers\Auth\PasswordResetController;
use App\Http\Controllers\Auth\RegistrationController;
use Illuminate\Contracts\View\View;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Laravel\Fortify\Http\Controllers\AuthenticatedSessionController;
use Laravel\Fortify\Http\Controllers\EmailVerificationNotificationController;
use Laravel\Fortify\Http\Controllers\EmailVerificationPromptController;
use Laravel\Fortify\Http\Controllers\TwoFactorAuthenticatedSessionController;
use Laravel\Fortify\Http\Controllers\VerifyEmailController;

Route::view('/', 'welcome')->name('home');
Route::view('/terms', 'legal.terms')->name('terms');
Route::view('/privacy', 'legal.privacy')->name('privacy');

Route::middleware('guest')->group(function (): void {
    Route::get('/two-factor-challenge', [TwoFactorAuthenticatedSessionController::class, 'create'])->name('two-factor.login');
    Route::post('/two-factor-challenge', [TwoFactorAuthenticatedSessionController::class, 'store'])->middleware('throttle:two-factor')->name('two-factor.login.store');
    Route::get('/login', [AuthenticatedSessionController::class, 'create'])->name('login');
    Route::post('/login', [AuthenticatedSessionController::class, 'store'])->middleware('throttle:login')->name('login.store');
    Route::view('/register', 'auth.register')->name('register');
    Route::post('/register', [RegistrationController::class, 'store'])->middleware('throttle:registration')->name('register.store');
    Route::view('/forgot-password', 'auth.forgot-password')->name('password.request');
    Route::post('/forgot-password', [PasswordResetController::class, 'request'])->middleware('throttle:forgot-password')->name('password.email');
    Route::get('/reset-password/{token}', function (Request $request, string $token): View {
        return view('auth.reset-password', ['token' => $token, 'email' => is_string($request->query('email')) ? $request->query('email') : '']);
    })->name('password.reset');
    Route::post('/reset-password', [PasswordResetController::class, 'reset'])->middleware('throttle:reset-password')->name('password.update');
});

Route::middleware('auth')->group(function (): void {
    Route::post('/logout', [AuthenticatedSessionController::class, 'destroy'])->name('logout');
    Route::get('/email/verify', EmailVerificationPromptController::class)->name('verification.notice');
    Route::get('/email/verify/{id}/{hash}', VerifyEmailController::class)->middleware(['signed', 'throttle:verification'])->name('verification.verify');
    Route::post('/email/verification-notification', [EmailVerificationNotificationController::class, 'store'])->middleware('throttle:verification')->name('verification.send');
});

Route::middleware(['auth', 'verified'])->prefix('account')->name('account.')->group(function (): void {
    Route::middleware('password.confirm:password.confirm,300')->group(function (): void {
        Route::get('/security', [SecurityController::class, 'show'])->name('security');
        Route::post('/two-factor', [SecurityController::class, 'enable'])->middleware('throttle:account-changes')->name('two-factor.enable');
        Route::post('/two-factor/confirm', [SecurityController::class, 'confirm'])->middleware('throttle:two-factor-settings')->name('two-factor.confirm');
        Route::post('/two-factor/recovery-codes', [SecurityController::class, 'regenerate'])->middleware('throttle:account-changes')->name('two-factor.regenerate');
        Route::delete('/two-factor', [SecurityController::class, 'disable'])->middleware('throttle:account-changes')->name('two-factor.disable');
    });
    Route::get('/profile', [ProfileController::class, 'show'])->name('profile');
    Route::get('/avatar', [ProfileController::class, 'avatar'])->name('avatar');
    Route::put('/profile', [ProfileController::class, 'update'])->middleware('throttle:account-changes')->name('profile.update');
    Route::put('/password', [ProfileController::class, 'password'])->middleware('throttle:account-changes')->name('password.update');
    Route::put('/email', [ProfileController::class, 'email'])->middleware('throttle:account-changes')->name('email.update');
    Route::get('/email/verify/{user}/{hash}', [ProfileController::class, 'verifyEmail'])->middleware(['signed', 'throttle:account-changes'])->name('email.verify');
});

Route::middleware(['auth', 'verified'])->group(function (): void {
    Route::get('/account/confirm-password', [SecurityController::class, 'passwordForm'])->name('password.confirm');
    Route::post('/account/confirm-password', [SecurityController::class, 'confirmPassword'])->middleware('throttle:password-confirmation')->name('password.confirm.store');
});
