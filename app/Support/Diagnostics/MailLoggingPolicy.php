<?php

namespace App\Support\Diagnostics;

use Illuminate\Contracts\Foundation\Application;
use RuntimeException;

final class MailLoggingPolicy
{
    public function enforce(Application $application): void
    {
        if ($application->environment(['local', 'testing'])) {
            return;
        }

        throw new RuntimeException('Mail body logging is forbidden outside local and testing environments.');
    }
}
