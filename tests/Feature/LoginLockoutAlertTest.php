<?php

use App\Enums\LoginLockoutStage;
use App\Enums\OAuthAuditEvent;
use App\Jobs\PrepareLoginLockoutAlert;
use App\Models\AuditLog;
use App\Models\User;
use App\Notifications\LoginLockoutAlert;
use App\Services\Authentication\QueueLoginLockoutAlert;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Notifications\SendQueuedNotifications;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Queue;
use Laravel\Fortify\Actions\EnableTwoFactorAuthentication;
use Tests\TestCase;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    $this->freezeTime();
    config(['queue.default' => 'database']);
    $this->realQueue = Queue::getFacadeRoot();
    $this->realNotifications = Notification::getFacadeRoot();
    Queue::fake();
    Notification::fake();
    $this->owner = User::factory()->create();
});

function passwordLockout(TestCase $test, string $email, string $ipAddress = '127.0.0.1'): void
{
    $test->withServerVariables(['REMOTE_ADDR' => $ipAddress]);
    for ($attempt = 0; $attempt < 5; $attempt++) {
        $test->postJson('/login', ['email' => $email, 'password' => 'private-attempt'])->assertUnprocessable();
    }
    $test->postJson('/login', ['email' => $email, 'password' => 'private-attempt'])
        ->assertTooManyRequests()->assertHeader('Retry-After', '60')->assertHeader('X-RateLimit-Remaining', '0');
}

function preparedLockout(LoginLockoutStage $stage, User $user): PrepareLoginLockoutAlert
{
    return new PrepareLoginLockoutAlert($stage, $stage === LoginLockoutStage::Password ? $user->email : null,
        $stage === LoginLockoutStage::TwoFactor ? $user->id : null, now()->toImmutable());
}

it('queues the same encrypted work on known and unknown account lockouts without mailing in the request', function (bool $known): void {
    $email = $known ? $this->owner->email : 'unknown@example.test';
    passwordLockout($this, $email);
    Queue::assertPushed(PrepareLoginLockoutAlert::class, function (PrepareLoginLockoutAlert $job) use ($email): bool {
        return $job instanceof ShouldBeEncrypted && $job->afterCommit && $job->email === $email
            && $job->userId === null && $job->stage === LoginLockoutStage::Password;
    });
    Queue::assertPushed(PrepareLoginLockoutAlert::class, 1);
    Notification::assertNothingSent();
    expect(AuditLog::where('event', OAuthAuditEvent::LoginLockedOut)->sole()->user_id)->toBeNull();
    $job = Queue::pushed(PrepareLoginLockoutAlert::class)->sole();
    $job->handle();
    if ($known) {
        Notification::assertSentTo($this->owner, LoginLockoutAlert::class);
    } else {
        Notification::assertNothingSent();
    }
})->with([true, false]);

it('bounds repeated rejected requests before account lookup and preserves each audit event', function (): void {
    passwordLockout($this, $this->owner->email);
    for ($attempt = 0; $attempt < 3; $attempt++) {
        $this->postJson('/login', ['email' => $this->owner->email, 'password' => 'private-attempt'])->assertTooManyRequests();
    }
    Queue::assertPushed(PrepareLoginLockoutAlert::class, 1);
    expect(AuditLog::where('event', OAuthAuditEvent::LoginLockedOut)->count())->toBe(4);
    $this->travel(61)->seconds();
    passwordLockout($this, $this->owner->email);
    Queue::assertPushed(PrepareLoginLockoutAlert::class, 2);
});

it('does not notify for IP-only throttling', function (): void {
    for ($attempt = 0; $attempt < 30; $attempt++) {
        $this->postJson('/login', ['email' => 'unknown'.$attempt.'@example.test', 'password' => 'private-attempt'])->assertUnprocessable();
    }
    $this->postJson('/login', ['email' => $this->owner->email, 'password' => 'private-attempt'])
        ->assertTooManyRequests()->assertHeader('Retry-After');
    Queue::assertNothingPushed();
    Notification::assertNothingSent();
    expect(AuditLog::where('event', OAuthAuditEvent::LoginLockedOut)->count())->toBe(1);
});

it('keeps second-factor IP-only throttles audit-only', function (): void {
    $users = User::factory()->count(6)->create();
    foreach ($users as $user) {
        $user->forceFill(['two_factor_secret' => encrypt('JBSWY3DPEHPK3PXP'),
            'two_factor_recovery_codes' => encrypt(json_encode(['fixture-recovery-code'])), 'two_factor_confirmed_at' => now()])->save();
        $this->withSession(['login.id' => $user->id]);
        for ($attempt = 0; $attempt < 5; $attempt++) {
            $this->postJson('/two-factor-challenge', ['recovery_code' => 'private-attempt'])->assertUnprocessable();
        }
    }
    $this->withSession(['login.id' => $this->owner->id])->postJson('/two-factor-challenge', ['recovery_code' => 'private-attempt'])
        ->assertTooManyRequests()->assertHeader('Retry-After');
    Queue::assertNothingPushed();
    expect(AuditLog::where('event', OAuthAuditEvent::LoginLockedOut)->sole()->user_id)->toBe($this->owner->id);
});

it('ignores malformed identifiers before optional queue work', function (): void {
    for ($attempt = 0; $attempt < 5; $attempt++) {
        $this->postJson('/login', ['email' => ['malformed'], 'password' => 'private-attempt'])->assertUnprocessable();
    }
    $this->postJson('/login', ['email' => ['malformed'], 'password' => 'private-attempt'])->assertTooManyRequests();
    Queue::assertNothingPushed();
});

it('uses only the server-held two-factor challenge identity', function (): void {
    app(EnableTwoFactorAuthentication::class)($this->owner);
    $this->owner->forceFill(['two_factor_confirmed_at' => now()])->save();
    $other = User::factory()->create();
    $this->post('/login', ['email' => $this->owner->email, 'password' => 'password'])->assertRedirect('/two-factor-challenge');
    for ($attempt = 0; $attempt < 5; $attempt++) {
        $this->postJson('/two-factor-challenge', ['recovery_code' => 'private-recovery-attempt'])->assertUnprocessable();
    }
    $this->postJson('/two-factor-challenge', ['recovery_code' => 'private-recovery-attempt', 'user_id' => $other->id, 'email' => $other->email])
        ->assertTooManyRequests()->assertHeader('Retry-After');
    Queue::assertPushed(PrepareLoginLockoutAlert::class, fn (PrepareLoginLockoutAlert $job): bool => $job->stage === LoginLockoutStage::TwoFactor && $job->userId === $this->owner->id && $job->email === null);
    expect(AuditLog::where('event', OAuthAuditEvent::LoginLockedOut)->sole()->user_id)->toBe($this->owner->id);
    Queue::pushed(PrepareLoginLockoutAlert::class)->sole()->handle();
    Notification::assertSentTo($this->owner, LoginLockoutAlert::class);
    Notification::assertNotSentTo($other, LoginLockoutAlert::class);
});

it('shares the twenty-four-hour claim across stages IPs and duplicate jobs', function (): void {
    $job = preparedLockout(LoginLockoutStage::Password, $this->owner);
    $job->handle();
    $job->handle();
    preparedLockout(LoginLockoutStage::TwoFactor, $this->owner)->handle();
    passwordLockout($this, $this->owner->email, '203.0.113.20');
    Queue::pushed(PrepareLoginLockoutAlert::class)->sole()->handle();
    Notification::assertSentToTimes($this->owner, LoginLockoutAlert::class, 1);
    $this->travel(24 * 60 * 60 - 1)->seconds();
    preparedLockout(LoginLockoutStage::Password, $this->owner)->handle();
    Notification::assertSentToTimes($this->owner, LoginLockoutAlert::class, 1);
    $this->travel(1)->seconds();
    preparedLockout(LoginLockoutStage::TwoFactor, $this->owner)->handle();
    Notification::assertSentToTimes($this->owner, LoginLockoutAlert::class, 2);
});

it('keeps independent accounts independent and never resets the daily claim on login', function (): void {
    preparedLockout(LoginLockoutStage::Password, $this->owner)->handle();
    $other = User::factory()->create();
    preparedLockout(LoginLockoutStage::Password, $other)->handle();
    $this->post('/login', ['email' => $this->owner->email, 'password' => 'password'])->assertRedirect();
    $this->post('/logout')->assertRedirect();
    preparedLockout(LoginLockoutStage::Password, $this->owner)->handle();
    Notification::assertSentToTimes($this->owner, LoginLockoutAlert::class, 1);
    Notification::assertSentToTimes($other, LoginLockoutAlert::class, 1);
});

it('skips unavailable unverified unknown or stale targets', function (string $state): void {
    $job = preparedLockout(LoginLockoutStage::Password, $this->owner);
    match ($state) {
        'pending' => $this->owner->forceFill(['deletion_requested_at' => now(), 'deletion_due_at' => now()->addDays(14)])->save(),
        'anonymized' => $this->owner->forceFill(['anonymized_at' => now()])->save(),
        'unverified' => $this->owner->forceFill(['email_verified_at' => null])->save(),
        'changed' => $this->owner->forceFill(['email' => 'different@example.test'])->save(),
        'stale' => $this->travel(601)->seconds(),
        'verified-later' => $this->owner->forceFill(['email_verified_at' => now()->addSecond()])->save(),
    };
    $job->handle();
    Notification::assertNothingSent();
    expect(Cache::has('login-lockout:account:'.$this->owner->id))->toBeFalse();
})->with(['pending', 'anonymized', 'unverified', 'changed', 'stale', 'verified-later']);

it('keeps the original 429 when asynchronous dispatch fails at transaction commit', function (): void {
    Bus::shouldReceive('dispatch')->twice()->andThrow(new RuntimeException('Synthetic queue failure'));
    passwordLockout($this, $this->owner->email);
    $this->postJson('/login', ['email' => $this->owner->email, 'password' => 'private-attempt'])
        ->assertTooManyRequests()->assertHeader('Retry-After', '60');
    expect(AuditLog::where('event', OAuthAuditEvent::LoginLockedOut)->count())->toBe(2);
});

it('keeps the throttle response when the alert cache fails', function (): void {
    for ($attempt = 0; $attempt < 5; $attempt++) {
        $this->postJson('/login', ['email' => $this->owner->email, 'password' => 'private-attempt'])->assertUnprocessable();
    }
    Cache::shouldReceive('add')->once()->andThrow(new RuntimeException('Synthetic cache failure'));
    $this->postJson('/login', ['email' => $this->owner->email, 'password' => 'private-attempt'])
        ->assertTooManyRequests()->assertHeader('Retry-After');
    Queue::assertNothingPushed();
});

it('preserves the response when queue failure cleanup also loses cache access', function (): void {
    Bus::shouldReceive('dispatch')->once()->andThrow(new RuntimeException('Synthetic queue failure'));
    Cache::shouldReceive('add')->once()->andReturnTrue();
    Cache::shouldReceive('forget')->once()->andThrow(new RuntimeException('Synthetic cache cleanup failure'));
    passwordLockout($this, $this->owner->email);
    Queue::assertNothingPushed();
});

it('uses the existing database cache for atomic daily claims', function (): void {
    config(['cache.default' => 'database']);
    $job = preparedLockout(LoginLockoutStage::Password, $this->owner);
    $job->handle();
    $job->handle();
    preparedLockout(LoginLockoutStage::TwoFactor, $this->owner)->handle();
    Notification::assertSentToTimes($this->owner, LoginLockoutAlert::class, 1);
    expect(Cache::get('login-lockout:account:'.$this->owner->id))->toBeTrue();
});

it('rejects process-local cache on a deployed worker without sending mail', function (): void {
    app()->instance('env', 'production');
    expect(fn () => preparedLockout(LoginLockoutStage::Password, $this->owner)->handle())
        ->toThrow(RuntimeException::class, 'shared atomic cache');
    Notification::assertNothingSent();
});

it('never runs account resolution synchronously from the public request', function (): void {
    config(['queue.default' => 'sync']);
    passwordLockout($this, $this->owner->email);
    Queue::assertNothingPushed();
    Notification::assertNothingSent();
});

it('releases the daily scheduling claim when notification enqueue fails', function (): void {
    Notification::shouldReceive('send')->twice()->andThrow(new RuntimeException('Synthetic mail enqueue failure'));
    $job = preparedLockout(LoginLockoutStage::Password, $this->owner);
    for ($attempt = 0; $attempt < 2; $attempt++) {
        expect(fn () => $job->handle())->toThrow(RuntimeException::class)
            ->and(Cache::has('login-lockout:account:'.$this->owner->id))->toBeFalse();
    }
});

it('rechecks the account address availability and freshness at notification delivery', function (string $change): void {
    $notification = new LoginLockoutAlert($this->owner->email, now()->toImmutable());
    expect($notification->shouldSend($this->owner, 'mail'))->toBeTrue();
    match ($change) {
        'email' => $this->owner->forceFill(['email' => 'new-address@example.test'])->save(),
        'pending' => $this->owner->forceFill(['deletion_requested_at' => now()])->save(),
        'unverified' => $this->owner->forceFill(['email_verified_at' => null])->save(),
        'stale' => $this->travel(601)->seconds(),
    };
    expect($notification->shouldSend($this->owner, 'mail'))->toBeFalse();
})->with(['email', 'pending', 'unverified', 'stale']);

it('does not queue alert work if the containing transaction rolls back', function (): void {
    DB::beginTransaction();
    $request = Request::create('/login', 'POST', ['email' => $this->owner->email]);
    app(QueueLoginLockoutAlert::class)->handle($request, LoginLockoutStage::Password);
    Queue::assertNothingPushed();
    DB::rollBack();
    Queue::assertNothingPushed();
});

it('processes both encrypted job stages through the real database queue without exposing credentials', function (): void {
    Queue::swap($this->realQueue);
    Notification::swap($this->realNotifications);
    passwordLockout($this, $this->owner->email);
    expect(DB::table('jobs')->count())->toBe(1);
    $payload = DB::table('jobs')->sole()->payload;
    expect($payload)->not->toContain($this->owner->email, 'private-attempt');
    $decoded = unserialize(app('encrypter')->decrypt(json_decode($payload, true)['data']['command']));
    expect($decoded)->toBeInstanceOf(PrepareLoginLockoutAlert::class)->and($decoded->email)->toBe($this->owner->email);
    Queue::connection('database')->pop()->fire();
    expect(DB::table('jobs')->count())->toBe(1);
    $payload = DB::table('jobs')->sole()->payload;
    expect($payload)->not->toContain($this->owner->email, 'private-attempt');
    $decoded = unserialize(app('encrypter')->decrypt(json_decode($payload, true)['data']['command']));
    expect($decoded)->toBeInstanceOf(SendQueuedNotifications::class)->and($decoded->shouldBeEncrypted)->toBeTrue();
    Queue::connection('database')->pop()->fire();
    expect(DB::table('jobs')->count())->toBe(0);
    $messages = Mail::mailer('array')->getSymfonyTransport()->messages();
    expect($messages)->toHaveCount(1);
    $html = $messages->sole()->getOriginalMessage()->getHtmlBody();
    expect($html)->toContain('temporarily rate limited', 'UTC', '/account/security', '24 hours')
        ->not->toContain('private-attempt', '127.0.0.1', '/reset-password/', 'successfully signed in');
});
