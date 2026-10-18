<?php

namespace App\Listeners;

use App\Enums\OAuthAuditEvent;
use App\Models\AuditLog;
use App\Models\User;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\Events\Verified;
use Illuminate\Support\Facades\Auth;
use Laravel\Fortify\Events\RecoveryCodesGenerated;
use Laravel\Fortify\Events\TwoFactorAuthenticationConfirmed;
use Laravel\Fortify\Events\TwoFactorAuthenticationDisabled;
use Laravel\Fortify\Events\TwoFactorAuthenticationFailed;

class RecordAuthenticationAudit
{
    public function handleLogin(Login $event): void
    {
        if ($event->guard === 'web' && $event->user instanceof User && request()->isMethod('POST')
            && request()->routeIs('login.store', 'two-factor.login.store') && ! Auth::guard('web')->viaRemember()) {
            $this->record(OAuthAuditEvent::LoginSucceeded, $event->user);
        }
    }

    public function handleFailed(Failed $event): void
    {
        if ($event->guard === 'web' && request()->isMethod('POST') && request()->routeIs('login.store')) {
            // A supplied email is not an authenticated actor. Use only the framework's
            // resolved account, when present, and never inspect or serialize credentials.
            $this->record(OAuthAuditEvent::LoginFailed, $event->user instanceof User ? $event->user : null);
        }
    }

    public function handleLogout(Logout $event): void
    {
        if ($event->guard === 'web' && $event->user instanceof User
            && request()->isMethod('POST') && request()->routeIs('logout')) {
            $this->record(OAuthAuditEvent::Logout, $event->user);
        }
    }

    public function handleTwoFactor(TwoFactorAuthenticationConfirmed|TwoFactorAuthenticationDisabled|TwoFactorAuthenticationFailed|RecoveryCodesGenerated $event): void
    {
        $type = match (true) {
            $event instanceof TwoFactorAuthenticationConfirmed && request()->routeIs('account.two-factor.confirm') => OAuthAuditEvent::TwoFactorEnabled,
            $event instanceof TwoFactorAuthenticationDisabled && request()->routeIs('account.two-factor.disable')
                && ($event->user->getPrevious()['two_factor_confirmed_at'] ?? null) !== null => OAuthAuditEvent::TwoFactorDisabled,
            $event instanceof TwoFactorAuthenticationFailed && request()->routeIs('two-factor.login.store') => OAuthAuditEvent::TwoFactorFailed,
            $event instanceof RecoveryCodesGenerated && request()->routeIs('account.two-factor.regenerate') => OAuthAuditEvent::RecoveryCodesRegenerated,
            default => null,
        };
        if ($type !== null) {
            $this->record($type, $event->user);
        }
    }

    public function handlePasswordReset(PasswordReset $event): void
    {
        if ($event->user instanceof User && request()->isMethod('POST') && request()->is('reset-password')) {
            $this->record(OAuthAuditEvent::PasswordReset, $event->user);
        }
    }

    public function handleVerification(Verified $event): void
    {
        if ($event->user instanceof User && request()->routeIs('verification.verify')) {
            $this->record(OAuthAuditEvent::EmailVerified, $event->user);
        }
    }

    private function record(OAuthAuditEvent $type, ?User $user): void
    {
        AuditLog::create(['user_id' => $user?->id, 'event' => $type]);
    }
}
