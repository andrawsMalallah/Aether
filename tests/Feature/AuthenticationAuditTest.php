<?php

use App\Enums\OAuthAuditEvent;
use App\Models\AuditLog;
use App\Models\User;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\URL;
use Laravel\Fortify\Actions\EnableTwoFactorAuthentication;
use Laravel\Fortify\Fortify;
use PragmaRX\Google2FA\Google2FA;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    Notification::fake();
    $this->owner = User::factory()->create();
});

it('records one completed sign-in and explicit logout but ignores programmatic events', function (): void {
    event(new Login('web', $this->owner, false));
    event(new Logout('web', $this->owner));
    expect(AuditLog::count())->toBe(0);
    $this->post('/login', ['email' => $this->owner->email, 'password' => 'password'])->assertRedirect();
    $this->post('/logout')->assertRedirect('/');
    expect(AuditLog::orderBy('id')->pluck('event')->all())->toBe([OAuthAuditEvent::LoginSucceeded, OAuthAuditEvent::Logout])
        ->and(AuditLog::where('user_id', $this->owner->id)->count())->toBe(2);
});

it('ignores remembered-session restoration even on login POST', function (): void {
    $guard = auth()->guard('web');
    $this->withCookie($guard->getRecallerName(), $this->owner->id.'|'.$this->owner->remember_token.'|'.$this->owner->password)
        ->post('/login', ['email' => $this->owner->email, 'password' => 'wrong'])->assertRedirect('/');
    expect($guard->viaRemember())->toBeTrue()->and(AuditLog::count())->toBe(0);
});

it('records known and unknown password failures without retaining supplied credentials', function (): void {
    $this->post('/login', ['email' => $this->owner->email, 'password' => 'wrong'])->assertSessionHasErrors('email');
    $this->post('/login', ['email' => 'unknown@example.test', 'password' => 'sensitive-attempt'])->assertSessionHasErrors('email');
    $logs = AuditLog::orderBy('id')->get();
    expect($logs->pluck('event')->all())->toBe([OAuthAuditEvent::LoginFailed, OAuthAuditEvent::LoginFailed])
        ->and($logs->pluck('user_id')->all())->toBe([$this->owner->id, null]);
    foreach ($logs as $log) {
        expect(array_keys($log->getAttributes()))->toBe(['id', 'user_id', 'client_id', 'event', 'created_at']);
    }
    expect($logs->toJson())->not->toContain('unknown@example.test', 'sensitive-attempt', $this->owner->email);
});

it('records a single throttle event and preserves 429 headers for password and IP limits', function (bool $sameEmail): void {
    $attempts = $sameEmail ? 5 : 30;
    for ($attempt = 0; $attempt < $attempts; $attempt++) {
        $this->post('/login', ['email' => $sameEmail ? $this->owner->email : 'unknown'.$attempt.'@example.test', 'password' => 'wrong'])
            ->assertSessionHasErrors('email');
    }
    $this->postJson('/login', ['email' => $this->owner->email, 'password' => 'wrong'])->assertTooManyRequests()
        ->assertHeader('Retry-After')->assertHeader('X-RateLimit-Remaining', '0');
    expect(AuditLog::where('event', OAuthAuditEvent::LoginLockedOut)->count())->toBe(1)
        ->and(AuditLog::where('event', OAuthAuditEvent::LoginLockedOut)->sole()->user_id)->toBeNull()
        ->and(AuditLog::where('event', OAuthAuditEvent::LoginFailed)->count())->toBe($attempts);
})->with([true, false]);

it('records failed second factors and their throttle without recording a successful login early', function (): void {
    app(EnableTwoFactorAuthentication::class)($this->owner);
    $this->owner->forceFill(['two_factor_confirmed_at' => now()])->save();
    $this->post('/login', ['email' => $this->owner->email, 'password' => 'password'])->assertRedirect('/two-factor-challenge');
    expect(AuditLog::count())->toBe(0);
    for ($attempt = 0; $attempt < 5; $attempt++) {
        $this->post('/two-factor-challenge', ['recovery_code' => 'invalid'])->assertSessionHasErrors('recovery_code');
    }
    $this->post('/two-factor-challenge', ['recovery_code' => 'invalid'])->assertTooManyRequests()->assertHeader('Retry-After');
    expect(AuditLog::where('event', OAuthAuditEvent::TwoFactorFailed)->count())->toBe(5)
        ->and(AuditLog::where('event', OAuthAuditEvent::LoginLockedOut)->sole()->user_id)->toBe($this->owner->id)
        ->and(AuditLog::where('event', OAuthAuditEvent::LoginSucceeded)->count())->toBe(0);
    $this->travel(61)->seconds();
    $this->post('/two-factor-challenge', ['recovery_code' => $this->owner->recoveryCodes()[0]])->assertRedirect();
    expect(AuditLog::where('event', OAuthAuditEvent::LoginSucceeded)->count())->toBe(1);
});

it('records confirmed 2FA activation regeneration and disable but not abandoned setup', function (): void {
    $this->actingAs($this->owner)->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    $this->post('/account/two-factor')->assertRedirect();
    expect(AuditLog::count())->toBe(0);
    $this->delete('/account/two-factor')->assertRedirect();
    expect(AuditLog::count())->toBe(0);
    $this->post('/account/two-factor')->assertRedirect();
    $secret = Fortify::currentEncrypter()->decrypt($this->owner->fresh()->two_factor_secret);
    $this->post('/account/two-factor/confirm', ['code' => 'invalid'])->assertSessionHasErrors('code');
    expect(AuditLog::count())->toBe(0);
    $this->post('/account/two-factor/confirm', ['code' => app(Google2FA::class)->getCurrentOtp($secret)])->assertRedirect();
    $this->post('/account/two-factor/recovery-codes')->assertRedirect();
    $this->delete('/account/two-factor')->assertRedirect();
    expect(AuditLog::orderBy('id')->pluck('event')->all())->toBe([
        OAuthAuditEvent::TwoFactorEnabled, OAuthAuditEvent::RecoveryCodesRegenerated, OAuthAuditEvent::TwoFactorDisabled,
    ]);
});

it('records password change and reset only for successful operations', function (): void {
    $this->actingAs($this->owner)->put('/account/password', ['current_password' => 'wrong', 'password' => 'New-Password-42!', 'password_confirmation' => 'New-Password-42!'])->assertSessionHasErrors('current_password');
    expect(AuditLog::count())->toBe(0);
    $this->put('/account/password', ['current_password' => 'password', 'password' => 'New-Password-42!', 'password_confirmation' => 'New-Password-42!'])->assertRedirect();
    expect(AuditLog::sole()->event)->toBe(OAuthAuditEvent::PasswordChanged);
    $this->post('/logout');
    $token = Password::broker()->createToken($this->owner);
    $attributes = ['email' => $this->owner->email, 'token' => $token, 'password' => 'Reset-Password-42!', 'password_confirmation' => 'Reset-Password-42!'];
    $this->post('/reset-password', [...$attributes, 'token' => 'invalid'])->assertSessionHasErrors('email');
    expect(AuditLog::where('event', OAuthAuditEvent::PasswordReset)->count())->toBe(0);
    $this->post('/reset-password', $attributes)->assertRedirect('/login');
    $this->post('/reset-password', $attributes)->assertSessionHasErrors('email');
    expect(AuditLog::where('event', OAuthAuditEvent::PasswordReset)->count())->toBe(1);
});

it('records initial email verification once and requested email changes with verification', function (): void {
    $user = User::factory()->unverified()->create();
    $url = URL::temporarySignedRoute('verification.verify', now()->addHour(), ['id' => $user->id, 'hash' => sha1($user->email)]);
    $this->actingAs($user)->get($url)->assertRedirect();
    $this->get($url)->assertRedirect();
    expect(AuditLog::where('event', OAuthAuditEvent::EmailVerified)->count())->toBe(1);
    $this->put('/account/email', ['email' => 'new@example.test', 'current_password' => 'password'])->assertRedirect();
    $url = URL::temporarySignedRoute('account.email.verify', now()->addHour(), ['user' => $user->id, 'hash' => sha1('new@example.test')]);
    $this->get($url)->assertRedirect();
    $this->get($url)->assertForbidden();
    expect(AuditLog::where('event', OAuthAuditEvent::EmailChangeRequested)->count())->toBe(1)
        ->and(AuditLog::where('event', OAuthAuditEvent::EmailVerified)->count())->toBe(2)
        ->and(AuditLog::get()->toJson())->not->toContain('new@example.test');
});

it('rolls back password changes and reset link consumption if the audit cannot be stored', function (bool $reset): void {
    $originalHash = $this->owner->password;
    $token = $reset ? Password::broker()->createToken($this->owner) : null;
    AuditLog::creating(function (AuditLog $audit): void {
        if (in_array($audit->event, [OAuthAuditEvent::PasswordChanged, OAuthAuditEvent::PasswordReset], true)) {
            throw new RuntimeException('Synthetic audit failure');
        }
    });
    try {
        if ($reset) {
            $this->post('/reset-password', ['email' => $this->owner->email, 'token' => $token, 'password' => 'Reset-Password-42!', 'password_confirmation' => 'Reset-Password-42!'])->assertServerError();
        } else {
            $this->actingAs($this->owner)->put('/account/password', ['current_password' => 'password', 'password' => 'New-Password-42!', 'password_confirmation' => 'New-Password-42!'])->assertServerError();
        }
        expect(hash_equals($originalHash, $this->owner->fresh()->password))->toBeTrue()->and(AuditLog::count())->toBe(0);
        if ($reset) {
            expect(Password::broker()->tokenExists($this->owner, $token))->toBeTrue();
        }
    } finally {
        AuditLog::flushEventListeners();
    }
})->with([true, false]);

it('rolls back initial verification when its audit fails', function (): void {
    $user = User::factory()->unverified()->create();
    AuditLog::creating(fn () => throw new RuntimeException('Synthetic audit failure'));
    try {
        $url = URL::temporarySignedRoute('verification.verify', now()->addHour(), ['id' => $user->id, 'hash' => sha1($user->email)]);
        $this->actingAs($user)->get($url)->assertServerError();
        expect($user->fresh()->hasVerifiedEmail())->toBeFalse()->and(AuditLog::count())->toBe(0);
    } finally {
        AuditLog::flushEventListeners();
    }
});

it('rolls back confirmed 2FA changes when their audit fails', function (string $operation): void {
    app(EnableTwoFactorAuthentication::class)($this->owner);
    if ($operation !== 'confirm') {
        $this->owner->forceFill(['two_factor_confirmed_at' => now()])->save();
    }
    $before = $this->owner->fresh();
    $this->actingAs($this->owner)->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    AuditLog::creating(fn () => throw new RuntimeException('Synthetic audit failure'));
    try {
        if ($operation === 'confirm') {
            $secret = Fortify::currentEncrypter()->decrypt($before->two_factor_secret);
            $this->post('/account/two-factor/confirm', ['code' => app(Google2FA::class)->getCurrentOtp($secret)])->assertServerError();
        } elseif ($operation === 'disable') {
            $this->delete('/account/two-factor')->assertServerError();
        } else {
            $this->post('/account/two-factor/recovery-codes')->assertServerError();
        }
        $after = $this->owner->fresh();
        expect($after->two_factor_confirmed_at?->timestamp)->toBe($before->two_factor_confirmed_at?->timestamp)
            ->and(hash_equals($before->two_factor_secret, $after->two_factor_secret))->toBeTrue()
            ->and(hash_equals($before->two_factor_recovery_codes, $after->two_factor_recovery_codes))->toBeTrue()
            ->and(AuditLog::count())->toBe(0);
    } finally {
        AuditLog::flushEventListeners();
    }
})->with(['confirm', 'disable', 'regenerate']);

it('rolls back email request or verification when their audit fails', function (bool $confirm): void {
    $originalEmail = $this->owner->email;
    if ($confirm) {
        $this->owner->forceFill(['pending_email' => 'pending@example.test', 'pending_email_requested_at' => now()])->save();
    }
    $this->actingAs($this->owner);
    AuditLog::creating(fn () => throw new RuntimeException('Synthetic audit failure'));
    try {
        if ($confirm) {
            $url = URL::temporarySignedRoute('account.email.verify', now()->addHour(), ['user' => $this->owner->id, 'hash' => sha1('pending@example.test')]);
            $this->get($url)->assertServerError();
        } else {
            $this->put('/account/email', ['email' => 'pending@example.test', 'current_password' => 'password'])->assertServerError();
            Notification::assertNothingSent();
        }
        expect($this->owner->fresh()->email)->toBe($originalEmail)
            ->and($this->owner->fresh()->pending_email)->toBe($confirm ? 'pending@example.test' : null)
            ->and(AuditLog::count())->toBe(0);
    } finally {
        AuditLog::flushEventListeners();
    }
})->with([true, false]);
