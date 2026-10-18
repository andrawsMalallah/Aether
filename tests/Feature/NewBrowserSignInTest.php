<?php

use App\Models\User;
use App\Notifications\NewBrowserSignIn;
use Illuminate\Auth\Events\Login;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Notifications\ChannelManager;
use Illuminate\Notifications\SendQueuedNotifications;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Queue;
use Laravel\Fortify\Actions\EnableTwoFactorAuthentication;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    Notification::fake();
    $this->owner = User::factory()->create();
    $this->browserCookie = 'aether_browser_'.hash('sha256', (string) $this->owner->id);
});

it('alerts once after successful login and issues an encrypted secure fixed-expiry marker', function (): void {
    $this->freezeTime();
    $response = $this->withHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0) Chrome/130.0')
        ->withServerVariables(['REMOTE_ADDR' => '192.0.2.10'])
        ->post('/login', ['email' => $this->owner->email, 'password' => 'password']);
    $response->assertRedirect('/account/profile')->assertCookie($this->browserCookie, (string) now()->addDays(90)->timestamp);
    Notification::assertSentToTimes($this->owner, NewBrowserSignIn::class, 1);
    Notification::assertSentTo($this->owner, NewBrowserSignIn::class, function (NewBrowserSignIn $notification): bool {
        $mail = $notification->toMail($this->owner);
        expect($notification->browser)->toBe('Chrome on Windows')
            ->and($notification->ipAddress)->toBe('192.0.2.10')
            ->and($notification->signedInAt)->toBe(now()->utc()->format('Y-m-d H:i:s').' UTC')
            ->and($mail->actionUrl)->toBe(url('/account/sessions'))
            ->and($notification->afterCommit)->toBeTrue();

        return true;
    });
    $cookie = $response->getCookie($this->browserCookie, false);
    expect($cookie->isSecure())->toBeTrue()->and($cookie->isHttpOnly())->toBeTrue()
        ->and($cookie->getSameSite())->toBe('lax')->and($cookie->getPath())->toBe('/')
        ->and($cookie->getExpiresTime())->toBe(now()->addDays(90)->timestamp)
        ->and($cookie->getValue())->not->toBe((string) now()->addDays(90)->timestamp);
});

it('does not alert for recognized browser even after an IP change or extend its retention', function (): void {
    $expires = (string) now()->addDays(30)->timestamp;
    $this->withCookie($this->browserCookie, $expires)->withServerVariables(['REMOTE_ADDR' => '192.0.2.20'])
        ->post('/login', ['email' => $this->owner->email, 'password' => 'password'])
        ->assertRedirect('/account/profile')->assertCookieMissing($this->browserCookie);
    Notification::assertNothingSent();
});

it('alerts again for expired malformed or tampered recognition', function (string $state): void {
    $value = match ($state) {
        'expired' => (string) now()->subSecond()->timestamp,
        'future' => (string) now()->addDays(91)->timestamp,
        default => 'tampered',
    };
    if ($state === 'tampered') {
        $this->withUnencryptedCookie($this->browserCookie, $value);
    } else {
        $this->withCookie($this->browserCookie, $value);
    }
    $this->post('/login', ['email' => $this->owner->email, 'password' => 'password'])->assertRedirect('/account/profile');
    Notification::assertSentToTimes($this->owner, NewBrowserSignIn::class, 1);
})->with(['expired', 'future', 'tampered', 'malformed']);

it('does not recognize another account from this accounts cookie', function (): void {
    $other = User::factory()->create();
    $this->withCookie($this->browserCookie, (string) now()->addDays(30)->timestamp)
        ->post('/login', ['email' => $other->email, 'password' => 'password'])->assertRedirect('/account/profile');
    Notification::assertSentToTimes($other, NewBrowserSignIn::class, 1);
    Notification::assertNotSentTo($this->owner, NewBrowserSignIn::class);
});

it('rejects an encrypted marker copied to another accounts cookie name', function (): void {
    $response = $this->post('/login', ['email' => $this->owner->email, 'password' => 'password']);
    $encrypted = $response->getCookie($this->browserCookie, false)->getValue();
    // HTTP tests reuse CookieJar; a real request starts with no outgoing cookies.
    Cookie::unqueue($this->browserCookie);
    $this->post('/logout');
    $other = User::factory()->create();
    $otherCookie = 'aether_browser_'.hash('sha256', (string) $other->id);
    $this->withUnencryptedCookie($otherCookie, $encrypted)
        ->post('/login', ['email' => $other->email, 'password' => 'password'])->assertRedirect('/account/profile');
    Notification::assertSentToTimes($other, NewBrowserSignIn::class, 1);
});

it('retains recognition through logout and still requires the password', function (): void {
    $response = $this->post('/login', ['email' => $this->owner->email, 'password' => 'password']);
    $encrypted = $response->getCookie($this->browserCookie, false)->getValue();
    Cookie::unqueue($this->browserCookie);
    $this->post('/logout')->assertCookieMissing($this->browserCookie);
    $this->withUnencryptedCookie($this->browserCookie, $encrypted);
    $this->post('/login', ['email' => $this->owner->email, 'password' => 'wrong'])->assertSessionHasErrors('email');
    $this->assertGuest();
    $this->post('/login', ['email' => $this->owner->email, 'password' => 'password'])->assertRedirect('/account/profile');
    Notification::assertSentToTimes($this->owner, NewBrowserSignIn::class, 1);
});

it('does not alert or recognize a failed password sign-in', function (): void {
    $this->post('/login', ['email' => $this->owner->email, 'password' => 'wrong'])
        ->assertSessionHasErrors('email')->assertCookieMissing($this->browserCookie);
    Notification::assertNothingSent();
    $this->assertGuest();
});

it('waits until the second factor succeeds before sending or recognizing', function (): void {
    app(EnableTwoFactorAuthentication::class)($this->owner);
    $this->owner->forceFill(['two_factor_confirmed_at' => now()])->save();
    $this->post('/login', ['email' => $this->owner->email, 'password' => 'password'])
        ->assertRedirect('/two-factor-challenge')->assertCookieMissing($this->browserCookie);
    $this->post('/two-factor-challenge', ['recovery_code' => 'invalid'])
        ->assertSessionHasErrors('recovery_code')->assertCookieMissing($this->browserCookie);
    Notification::assertNothingSent();
    $this->assertGuest();
    $this->post('/two-factor-challenge', ['recovery_code' => $this->owner->recoveryCodes()[0]])
        ->assertRedirect('/account/profile')->assertCookie($this->browserCookie);
    Notification::assertSentToTimes($this->owner, NewBrowserSignIn::class, 1);
    $this->assertAuthenticatedAs($this->owner);
});

it('ignores remembered-session restoration and programmatic logins', function (): void {
    event(new Login('web', $this->owner, true));
    event(new Login('other', $this->owner, false));
    $this->actingAs($this->owner)->get('/account/profile')->assertOk();
    Notification::assertNothingSent();
});

it('does not alert when a remember cookie restores the user on the login POST itself', function (): void {
    $guard = auth()->guard('web');
    $recaller = $this->owner->id.'|'.$this->owner->remember_token.'|'.$this->owner->password;
    $this->withCookie($guard->getRecallerName(), $recaller)
        ->post('/login', ['email' => $this->owner->email, 'password' => 'wrong'])
        ->assertRedirect('/')->assertCookieMissing($this->browserCookie);
    expect($guard->viaRemember())->toBeTrue();
    Notification::assertNothingSent();
});

it('queues encrypted mail instead of delivering in the login request', function (): void {
    Notification::swap(new ChannelManager(app()));
    Queue::fake();
    $this->post('/login', ['email' => $this->owner->email, 'password' => 'password'])->assertRedirect('/account/profile');
    Queue::assertPushed(SendQueuedNotifications::class, function (SendQueuedNotifications $job): bool {
        return $job->notification instanceof NewBrowserSignIn
            && $job->notification instanceof ShouldBeEncrypted && $job->shouldBeEncrypted && $job->afterCommit;
    });
    Queue::assertPushed(SendQueuedNotifications::class, 1);
});

it('renders the queued mail through the real channel without exposing recognition data', function (): void {
    Notification::swap(new ChannelManager(app()));
    $notification = new NewBrowserSignIn('Firefox on Linux', '192.0.2.40', '2026-10-18 12:00:00 UTC');
    Notification::sendNow($this->owner, $notification);
    $messages = app('mailer')->getSymfonyTransport()->messages();
    expect($messages)->toHaveCount(1);
    $mail = $messages->first()->getOriginalMessage();
    expect($mail->getSubject())->toBe('New browser sign-in to Aether')
        ->and($mail->getHtmlBody())->toContain('Firefox on Linux', '192.0.2.40', '2026-10-18 12:00:00 UTC', '/account/sessions')
        ->not->toContain('aether_browser_', 'remember_token', 'two_factor_secret');
});
