<?php

use App\Actions\Account\RevokeSessions;
use App\Models\User;
use Illuminate\Auth\SessionGuard;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Session\DatabaseSessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;

uses(RefreshDatabase::class);

function sessionPolicyGuard(): SessionGuard
{
    $store = new Store('policy-test-session', new DatabaseSessionHandler(DB::connection(), 'sessions', 120, app()));
    $store->start();
    app()->instance('session.store', $store);

    return app('auth')->createSessionDriver('web', config('auth.guards.web'));
}

it('issues thirty-day remember cookies through the real login while retaining the idle default', function (): void {
    Notification::fake();
    $this->freezeTime();
    $user = User::factory()->create();
    $guard = auth()->guard('web');
    expect(config('session.lifetime'))->toBe(120);
    $response = $this->post('/login', ['email' => $user->email, 'password' => 'password', 'remember' => '1'])
        ->assertRedirect('/account/profile');
    $cookie = $response->getCookie($guard->getRecallerName());
    expect($cookie)->not->toBeNull()
        ->and($cookie->getExpiresTime())->toBe(now()->addDays(30)->timestamp)
        ->and($cookie->isHttpOnly())->toBeTrue()
        ->and($cookie->getSameSite())->toBe('lax');
});

it('does not issue a remember cookie when remember me is unchecked', function (): void {
    Notification::fake();
    $user = User::factory()->create();
    $this->post('/login', ['email' => $user->email, 'password' => 'password'])
        ->assertRedirect('/account/profile')->assertCookieMissing(auth()->guard('web')->getRecallerName());
});

it('retains recent sessions and expires idle database sessions without a remember cookie', function (int $idleMinutes, bool $authenticated): void {
    $user = User::factory()->create();
    $guard = sessionPolicyGuard();
    $guard->login($user);
    $guard->getSession()->save();
    $sessionId = $guard->getSession()->getId();
    DB::table('sessions')->where('id', $sessionId)->update(['last_activity' => now()->subMinutes($idleMinutes)->timestamp]);
    $store = new Store('expired-policy-session', new DatabaseSessionHandler(DB::connection(), 'sessions', 120, app()));
    $store->setId($sessionId);
    $store->start();
    app()->instance('session.store', $store);
    $freshGuard = app('auth')->createSessionDriver('web', config('auth.guards.web'));
    $freshGuard->setRequest(Request::create('/account/profile'));
    expect($freshGuard->check())->toBe($authenticated);
    if ($authenticated) {
        expect($freshGuard->user()?->id)->toBe($user->id);
    } else {
        expect($store->all())->not->toHaveKey($guard->getName());
    }
})->with(['recent session' => [119, true], 'expired session' => [121, false]]);

it('restores unexpired current and legacy remember cookies without rotating credentials', function (bool $legacy): void {
    $user = User::factory()->create();
    $oldGuard = sessionPolicyGuard();
    if ($legacy) {
        $oldGuard->setRememberDuration(576000);
    }
    $oldGuard->login($user, true);
    $cookie = Cookie::queued($oldGuard->getRecallerName());
    $rememberToken = $user->fresh()->remember_token;
    // Model an old cookie whose browser expiry still permits it after day thirty.
    $this->travel($legacy ? 31 : 1)->days();
    Cookie::flushQueuedCookies();
    $freshGuard = sessionPolicyGuard();
    $freshGuard->setRequest(Request::create('/account/profile', 'GET', [], [$cookie->getName() => $cookie->getValue()]));
    expect($cookie->getExpiresTime())->toBeGreaterThan(now()->timestamp)
        ->and($freshGuard->user()?->id)->toBe($user->id)
        ->and($freshGuard->viaRemember())->toBeTrue()
        ->and($user->fresh()->remember_token)->toBe($rememberToken)
        ->and($freshGuard->getSession()->has('auth.password_confirmed_at'))->toBeFalse();
})->with(['legacy cookie after day thirty' => true, 'current cookie' => false]);

it('preserves existing session revocation for thirty-day remembered sign-ins', function (): void {
    config(['session.driver' => 'database', 'session.connection' => null]);
    $user = User::factory()->create();
    $guard = sessionPolicyGuard();
    $guard->login($user, true);
    $guard->getSession()->save();
    $cookie = Cookie::queued($guard->getRecallerName());
    $sessionId = $guard->getSession()->getId();
    Cookie::flushQueuedCookies();
    // Keep a distinct current session while revoking all other fixture sessions.
    app(RevokeSessions::class)->handle($user, 'retained-current-session', null);
    expect(DB::table('sessions')->where('id', $sessionId)->exists())->toBeFalse();
    $freshGuard = sessionPolicyGuard();
    $freshGuard->setRequest(Request::create('/account/profile', 'GET', [], [$cookie->getName() => $cookie->getValue()]));
    expect($freshGuard->user())->toBeNull()->and($freshGuard->viaRemember())->toBeFalse();
});
