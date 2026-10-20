<?php

namespace App\Services\Authentication;

use App\Enums\LoginLockoutStage;
use App\Jobs\PrepareLoginLockoutAlert;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Str;
use RuntimeException;
use Throwable;

class QueueLoginLockoutAlert
{
    public function handle(Request $request, LoginLockoutStage $stage): void
    {
        $email = null;
        $userId = null;
        if ($stage === LoginLockoutStage::Password) {
            $submittedEmail = $request->input('email');
            if (! is_string($submittedEmail) || strlen($submittedEmail) > 1020) {
                return;
            }
            $email = Str::lower(trim($submittedEmail));
            // Throttling runs before Fortify's FormRequest. This optional alert must not
            // introduce validation responses or account lookups into the public request.
            if (Validator::make(['email' => $email], ['email' => ['required', 'string', 'email', 'max:255']])->fails()) {
                return;
            }
            $identity = 'email:'.hash('sha256', $email);
        } else {
            $challengeId = $request->session()->get('login.id');
            $userId = filter_var($challengeId, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
            if ($userId === false) {
                return;
            }
            $identity = 'challenge:'.$userId;
        }

        try {
            $connection = config('queue.default');
            if (! in_array(config('queue.connections.'.$connection.'.driver'), ['database', 'redis', 'beanstalkd', 'sqs'], true)) {
                throw new RuntimeException('Lockout alerts require an asynchronous queue connection.');
            }
            $this->ensureSharedCache();

            // Bound repeat rejected requests before account resolution. Both known and
            // unknown addresses follow this same path; only a digest is kept in cache.
            $key = 'login-lockout:intake:'.$identity;
            if (! Cache::add($key, true, 60)) {
                return;
            }
            try {
                $job = (new PrepareLoginLockoutAlert($stage, $email, $userId, now()->toImmutable()))->afterCommit();
                // Login is serialized in a user transaction. Catch enqueue failures inside
                // its commit callback, otherwise an outage can replace the completed 429.
                DB::afterCommit(function () use ($job, $key): void {
                    try {
                        Bus::dispatch($job);
                    } catch (Throwable $exception) {
                        $this->releaseIntakeClaim($key);
                        report($exception);
                    }
                });
            } catch (Throwable $exception) {
                $this->releaseIntakeClaim($key);
                throw $exception;
            }
        } catch (Throwable $exception) {
            // Mail/queue/cache availability must never change the throttle response.
            report($exception);
        }
    }

    public function ensureSharedCache(): void
    {
        $store = config('cache.default');
        if (! in_array(config('cache.stores.'.$store.'.driver'), ['database', 'redis', 'memcached'], true)
            && ! (app()->environment('testing') && config('cache.stores.'.$store.'.driver') === 'array')) {
            throw new RuntimeException('Lockout alerts require a shared atomic cache store.');
        }
    }

    private function releaseIntakeClaim(string $key): void
    {
        try {
            Cache::forget($key);
        } catch (Throwable $exception) {
            // A failed best-effort cleanup only suppresses intake until the one-minute expiry.
            report($exception);
        }
    }
}
