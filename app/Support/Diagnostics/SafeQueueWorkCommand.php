<?php

namespace App\Support\Diagnostics;

use Illuminate\Contracts\Queue\Job;
use Illuminate\Queue\Console\WorkCommand;
use Throwable;

class SafeQueueWorkCommand extends WorkCommand
{
    protected function writeOutput(Job $job, mixed $status, ?Throwable $exception = null): void
    {
        // Sanitize only the displayed copy; retries, failure callbacks and events retain the real error.
        parent::writeOutput($job, $status, $exception === null ? null : new SafeDiagnosticException($exception));
    }
}
