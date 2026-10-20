<?php

namespace Tests\Support;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use RuntimeException;
use Throwable;

class FailingDiagnosticsJob implements ShouldBeEncrypted, ShouldQueue
{
    use Queueable;

    public static ?string $failureMessage = null;

    public function handle(): void
    {
        throw new RuntimeException('worker-diagnostic-sentinel');
    }

    public function failed(Throwable $exception): void
    {
        self::$failureMessage = $exception->getMessage();
    }
}
