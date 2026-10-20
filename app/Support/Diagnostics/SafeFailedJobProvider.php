<?php

namespace App\Support\Diagnostics;

use Illuminate\Queue\Failed\DatabaseUuidFailedJobProvider;

class SafeFailedJobProvider extends DatabaseUuidFailedJobProvider
{
    public function log(mixed $connection, mixed $queue, mixed $payload, mixed $exception): ?string
    {
        return parent::log($connection, $queue, $payload, new SafeDiagnosticException($exception));
    }
}
