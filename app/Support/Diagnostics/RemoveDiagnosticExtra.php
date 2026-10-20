<?php

namespace App\Support\Diagnostics;

use Monolog\LogRecord;

final class RemoveDiagnosticExtra
{
    public function __invoke(LogRecord $record): LogRecord
    {
        // Laravel's ContextLogProcessor runs after the Logger boundary and may carry request data.
        return $record->with(extra: []);
    }
}
