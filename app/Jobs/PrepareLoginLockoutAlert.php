<?php

namespace App\Jobs;

use App\Enums\LoginLockoutStage;
use App\Models\User;
use App\Notifications\LoginLockoutAlert;
use App\Services\Authentication\QueueLoginLockoutAlert;
use Carbon\CarbonImmutable;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Support\Facades\Cache;
use Throwable;

class PrepareLoginLockoutAlert implements ShouldBeEncrypted, ShouldQueue
{
    use Queueable;

    public int $tries = 3;

    public int $timeout = 30;

    public int $backoff = 30;

    public function __construct(
        public readonly LoginLockoutStage $stage,
        public readonly ?string $email,
        public readonly ?int $userId,
        public readonly CarbonImmutable $occurredAt,
    ) {}

    public function handle(): void
    {
        app(QueueLoginLockoutAlert::class)->ensureSharedCache();
        if ($this->occurredAt->isFuture() || $this->occurredAt->addMinutes(10)->isPast()) {
            return;
        }
        $query = User::query()->select(['id', 'email', 'email_verified_at', 'deletion_requested_at', 'anonymized_at']);
        $user = $this->stage === LoginLockoutStage::Password
            ? $query->where('email', $this->email)->first()
            : $query->whereKey($this->userId)->first();
        if ($user === null || ! $user->accountAvailable() || ! $user->hasVerifiedEmail()
            || $user->email_verified_at?->isAfter($this->occurredAt)) {
            return;
        }

        // One shared account claim spans addresses, IPs and both login stages.
        // SMTP is at-least-once delivery; this bounds newly scheduled notifications.
        $key = 'login-lockout:account:'.$user->id;
        if (! Cache::add($key, true, 24 * 60 * 60)) {
            return;
        }
        try {
            $user->notify(new LoginLockoutAlert($user->email, $this->occurredAt));
        } catch (Throwable $exception) {
            Cache::forget($key);
            throw $exception;
        }
    }
}
