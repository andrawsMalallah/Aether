<?php

namespace App\Support\Diagnostics;

use Illuminate\Log\Logger;
use Illuminate\Log\LogManager;
use Monolog\Logger as MonologLogger;
use RuntimeException;

class SafeLogManager extends LogManager
{
    protected function tap(mixed $name, Logger $logger): Logger
    {
        // Log mail is an intentional local-only content sink, never an application diagnostic sink.
        if ($name === 'local-mail' && $this->app->environment(['local', 'testing'])) {
            return parent::tap($name, $logger);
        }

        $underlying = $logger->getLogger();
        if (! $underlying instanceof MonologLogger) {
            throw new RuntimeException('The configured logger requires a reviewed safe diagnostics adapter.');
        }
        $underlying->pushProcessor(new RemoveDiagnosticExtra);

        return parent::tap($name, new SafeLogger($logger->getLogger(), $this->app['events']));
    }

    protected function createEmergencyLogger(): Logger
    {
        $logger = parent::createEmergencyLogger();
        if (! $logger instanceof Logger) {
            throw new RuntimeException('Emergency diagnostics logger is unavailable.');
        }

        return new SafeLogger($logger->getLogger(), $this->app['events']);
    }
}
