<?php

namespace App\Support\Diagnostics;

use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Contracts\Support\Jsonable;
use Illuminate\Log\Logger;
use Illuminate\Support\Stringable;
use Throwable;

class SafeLogger extends Logger
{
    /**
     * @param  Arrayable<array-key, mixed>|Jsonable|Stringable|array<array-key, mixed>|string  $message
     * @param  array<string, mixed>  $context
     */
    protected function writeLog(mixed $level, mixed $message, mixed $context): void
    {
        $exception = $context['exception'] ?? null;
        $diagnostic = $exception instanceof Throwable ? SafeDiagnostic::describe($exception) : [];

        // Arbitrary text cannot be reliably scrubbed: even driver messages can contain credentials.
        // Clear shared context before both Monolog handlers and Laravel MessageLogged listeners.
        $this->context = [];
        parent::writeLog($level, $exception instanceof Throwable ? 'Application exception.' : 'Application diagnostic.', $diagnostic);
    }
}
