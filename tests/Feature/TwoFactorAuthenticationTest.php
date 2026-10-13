<?php

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Laravel\Fortify\Actions\EnableTwoFactorAuthentication;
use Laravel\Fortify\Fortify;
use PragmaRX\Google2FA\Google2FA;

uses(RefreshDatabase::class);

function authenticatorCode(User $user): string
{
    return app(Google2FA::class)->getCurrentOtp(Fortify::currentEncrypter()->decrypt($user->fresh()->two_factor_secret));
}

it('requires authentication verification and fresh password confirmation', function (): void {
    $this->get('/account/security')->assertRedirect('/login');
    $user = User::factory()->unverified()->create();
    $this->actingAs($user)->get('/account/security')->assertRedirect('/email/verify');
    $user->markEmailAsVerified();
    $this->get('/account/security')->assertRedirect('/account/confirm-password');
    $this->post('/account/confirm-password', ['password' => []])->assertSessionHasErrors('password');
    $this->post('/account/confirm-password', ['password' => 'wrong'])->assertSessionHasErrors('password');
    $this->post('/account/confirm-password', ['password' => 'password'])->assertRedirect('/account/security');
    $this->get('/account/security')->assertOk()->assertHeader('Cache-Control', 'no-store, private');
    $this->travel(301)->seconds();
    $this->post('/account/two-factor')->assertRedirect('/account/confirm-password');
    expect($user->fresh()->two_factor_secret)->toBeNull();
});

it('confirms setup before requiring TOTP and displays recovery codes only once', function (): void {
    $user = User::factory()->create();
    $this->actingAs($user)->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    $this->post('/account/two-factor')->assertRedirect('/account/security');
    expect($user->fresh()->hasEnabledTwoFactorAuthentication())->toBeFalse();
    $secret = Fortify::currentEncrypter()->decrypt($user->fresh()->two_factor_secret);
    expect($user->fresh()->two_factor_secret)->not->toBe($secret);
    expect($user->fresh()->toArray())->not->toHaveKeys(['two_factor_secret', 'two_factor_recovery_codes']);
    $this->get('/account/security')->assertOk()->assertSee('Authenticator setup QR code');
    $this->post('/account/two-factor/confirm', ['code' => ['invalid']])->assertSessionHasErrors('code');
    $wrongCode = authenticatorCode($user) === '000000' ? '999999' : '000000';
    $this->post('/account/two-factor/confirm', ['code' => $wrongCode])->assertSessionHasErrors('code');
    expect($user->fresh()->hasEnabledTwoFactorAuthentication())->toBeFalse();
    $this->post('/account/two-factor/confirm', ['code' => authenticatorCode($user)])->assertRedirect('/account/security');
    expect($user->fresh()->hasEnabledTwoFactorAuthentication())->toBeTrue();
    $recoveryCode = $user->fresh()->recoveryCodes()[0];
    $this->get('/account/security')->assertSee($recoveryCode)->assertDontSee($secret);
    $this->get('/account/security')->assertDontSee($recoveryCode);
    $this->post('/account/two-factor/confirm', ['code' => authenticatorCode($user)])->assertStatus(409);
    $this->post('/logout');
    $this->post('/login', ['email' => $user->email, 'password' => 'password'])->assertRedirect('/two-factor-challenge');
    $this->assertGuest();
    $this->get('/account/profile')->assertRedirect('/login');
    $this->get('/two-factor-challenge')->assertOk();
    // Use the next accepted time step: the setup code has already been consumed.
    $engine = app(Google2FA::class);
    $nextCode = $engine->oathTotp($secret, $engine->getTimestamp() + 1);
    $this->post('/two-factor-challenge', ['code' => $nextCode])->assertRedirect('/account/profile');
    $this->assertAuthenticatedAs($user);
});

it('allows ordinary login while setup is unconfirmed and cancellation removes credentials', function (): void {
    $user = User::factory()->create();
    app(EnableTwoFactorAuthentication::class)($user);
    $this->post('/login', ['email' => $user->email, 'password' => 'password'])->assertRedirect('/account/profile');
    $this->withSession(['auth.password_confirmed_at' => now()->timestamp])->delete('/account/two-factor')->assertRedirect('/account/security');
    expect($user->fresh()->two_factor_secret)->toBeNull()
        ->and($user->fresh()->two_factor_recovery_codes)->toBeNull()
        ->and($user->fresh()->two_factor_confirmed_at)->toBeNull();
});

it('consumes recovery codes and invalidates previous codes after regeneration', function (): void {
    $user = User::factory()->create();
    app(EnableTwoFactorAuthentication::class)($user);
    $user->forceFill(['two_factor_confirmed_at' => now()])->save();
    $oldCode = $user->recoveryCodes()[0];
    $this->post('/login', ['email' => $user->email, 'password' => 'password', 'remember' => '1']);
    $this->post('/two-factor-challenge', ['recovery_code' => $oldCode])->assertRedirect('/account/profile');
    $this->assertAuthenticatedAs($user);
    expect($user->fresh()->recoveryCodes())->not->toContain($oldCode);
    expect($user->fresh()->remember_token)->not->toBeNull();
    $remainingCode = $user->fresh()->recoveryCodes()[0];
    $this->withSession(['auth.password_confirmed_at' => now()->timestamp])->post('/account/two-factor/recovery-codes')->assertRedirect('/account/security');
    expect($user->fresh()->recoveryCodes())->not->toContain($remainingCode);
    $newCode = $user->fresh()->recoveryCodes()[0];
    $this->get('/account/security')->assertSee($newCode);
    $this->get('/account/security')->assertDontSee($newCode);
    $this->post('/logout');
    $this->post('/login', ['email' => $user->email, 'password' => 'password']);
    $this->post('/two-factor-challenge', ['recovery_code' => $oldCode])->assertSessionHasErrors('recovery_code');
    $this->post('/two-factor-challenge', ['recovery_code' => $remainingCode])->assertSessionHasErrors('recovery_code');
    $this->assertGuest();
    $this->post('/two-factor-challenge', ['recovery_code' => $newCode])->assertRedirect('/account/profile');
});

it('limits challenge attempts across fresh sessions for the same account', function (): void {
    $user = User::factory()->create();
    app(EnableTwoFactorAuthentication::class)($user);
    $user->forceFill(['two_factor_confirmed_at' => now()])->save();
    $this->post('/login', ['email' => $user->email, 'password' => 'password']);
    for ($attempt = 0; $attempt < 5; $attempt++) {
        $this->post('/two-factor-challenge', ['code' => 'invalid'])->assertSessionHasErrors('code');
    }
    $this->withSession(['login.id' => $user->id])->post('/two-factor-challenge', ['recovery_code' => $user->recoveryCodes()[0]])->assertTooManyRequests();
    $this->travel(61)->seconds();
    $this->post('/two-factor-challenge', ['recovery_code' => $user->recoveryCodes()[0]])->assertRedirect('/account/profile');
});

it('does not allow challenges without a password login', function (): void {
    $this->get('/two-factor-challenge')->assertRedirect('/login');
    $this->post('/two-factor-challenge', ['code' => []])->assertSessionHasErrors('code');
    $this->assertGuest();
});

it('rejects and limits incorrect TOTP setup without flashing the code', function (): void {
    $user = User::factory()->create();
    $this->actingAs($user)->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    $this->post('/account/two-factor');
    for ($attempt = 0; $attempt < 5; $attempt++) {
        $this->post('/account/two-factor/confirm', ['code' => 'invalid'])
            ->assertSessionHasErrors('code')->assertSessionMissing('_old_input.code');
    }
    $this->post('/account/two-factor/confirm', ['code' => authenticatorCode($user)])->assertTooManyRequests();
    expect($user->fresh()->hasEnabledTwoFactorAuthentication())->toBeFalse();
});

it('disables confirmed 2FA and rejects regeneration without confirmed setup', function (): void {
    $user = User::factory()->create();
    app(EnableTwoFactorAuthentication::class)($user);
    $this->actingAs($user)->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    $this->post('/account/two-factor/recovery-codes')->assertStatus(409);
    $user->forceFill(['two_factor_confirmed_at' => now()])->save();
    $this->delete('/account/two-factor')->assertRedirect('/account/security');
    expect($user->fresh()->hasEnabledTwoFactorAuthentication())->toBeFalse()
        ->and($user->fresh()->two_factor_secret)->toBeNull()
        ->and($user->fresh()->two_factor_recovery_codes)->toBeNull();
    $this->post('/logout');
    $this->post('/login', ['email' => $user->email, 'password' => 'password'])->assertRedirect('/account/profile');
});

it('rate limits password confirmation', function (): void {
    $this->actingAs(User::factory()->create());
    for ($attempt = 0; $attempt < 5; $attempt++) {
        $this->post('/account/confirm-password', ['password' => 'wrong'])->assertSessionHasErrors('password');
    }
    $this->post('/account/confirm-password', ['password' => 'password'])->assertTooManyRequests();
});

it('protects every settings mutation with password confirmation', function (string $method, string $path): void {
    $user = User::factory()->create();
    $this->actingAs($user)->call($method, $path)->assertRedirect('/account/confirm-password');
    expect($user->fresh()->two_factor_secret)->toBeNull();
})->with([
    ['POST', '/account/two-factor'], ['POST', '/account/two-factor/confirm'],
    ['POST', '/account/two-factor/recovery-codes'], ['DELETE', '/account/two-factor'],
]);
