<?php

namespace App\Exceptions;

use App\Support\Diagnostics\SafeDiagnostic;
use Illuminate\Foundation\Exceptions\Handler as FrameworkHandler;
use Symfony\Component\Console\Formatter\OutputFormatter;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\HttpFoundation\Response;
use Throwable;

class Handler extends FrameworkHandler
{
    public function render($request, Throwable $e): Response
    {
        // Operational probes stay fixed even when a provider fails before route dispatch.
        if ($request->is('ready')) {
            return response('Unavailable', 503)->header('Content-Type', 'text/plain; charset=UTF-8')
                ->header('Cache-Control', 'no-store');
        }

        return parent::render($request, $e);
    }

    /** @param OutputInterface $output */
    public function renderForConsole($output, Throwable $exception): void
    {
        // Console rendering bypasses logging, including worker stderr and verbose traces.
        $output->writeln(OutputFormatter::escape(SafeDiagnostic::text($exception)));
    }
}
