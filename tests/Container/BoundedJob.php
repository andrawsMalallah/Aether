<?php

use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

require_once '/var/www/html/vendor/autoload.php';

// Loaded through a test-only PHP ini mount; never copied to the runtime image.
class ContainerBoundedJob implements ShouldBeEncrypted, ShouldQueue
{
    use Queueable;

    public int $timeout = 30;

    public function handle(): void
    {
        Log::error('CONTAINER_SENSITIVE_CANARY', ['token' => 'CONTAINER_SENSITIVE_CANARY']);
        Cache::put('container-drain-started', true, 600);
        $deadline = microtime(true) + 8;
        // A signal can interrupt sleep; keep doing bounded work until completion.
        while (microtime(true) < $deadline) {
            usleep(100000);
        }
        Cache::put('container-drain-finished', true, 600);
    }
}
