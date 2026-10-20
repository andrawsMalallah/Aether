<?php

namespace App\Exceptions;

use App\Support\Diagnostics\SafeDiagnostic;
use Illuminate\Foundation\Exceptions\Handler as FrameworkHandler;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Output\OutputInterface;
use Throwable;

class Handler extends FrameworkHandler
{
    /** @param OutputInterface $output */
    public function renderForConsole($output, Throwable $exception): void
    {
        // Console rendering bypasses logging, including worker stderr and verbose traces.
        $output->writeln(OutputFormatter::escape(SafeDiagnostic::text($exception)));
    }
}
