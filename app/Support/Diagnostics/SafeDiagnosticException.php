<?php

namespace App\Support\Diagnostics;

use RuntimeException;
use Throwable;

final class SafeDiagnosticException extends RuntimeException
{
    public function __construct(Throwable $exception)
    {
        // Never retain the original throwable as a previous exception or property.
        parent::__construct(SafeDiagnostic::text($exception));
    }

    public function __toString(): string
    {
        return $this->getMessage();
    }
}
