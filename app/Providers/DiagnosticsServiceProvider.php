<?php

namespace App\Providers;

use App\Support\Diagnostics\MailLoggingPolicy;
use App\Support\Diagnostics\SafeFailedJobProvider;
use App\Support\Diagnostics\SafeQueueWorkCommand;
use Illuminate\Mail\MailManager;
use Illuminate\Mail\Transport\LogTransport;
use Illuminate\Queue\Console\WorkCommand;
use Illuminate\Queue\Failed\NullFailedJobProvider;
use Illuminate\Support\ServiceProvider;
use RuntimeException;

class DiagnosticsServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->extend('queue.failer', function ($provider, $application): SafeFailedJobProvider|NullFailedJobProvider {
            $configuration = $application['config']['queue.failed'];
            if ($provider instanceof NullFailedJobProvider) {
                return $provider;
            }
            if (($configuration['driver'] ?? null) !== 'database-uuids') {
                throw new RuntimeException('The configured failed-job storage requires a reviewed safe diagnostics adapter.');
            }

            return new SafeFailedJobProvider($application['db'], $configuration['database'], $configuration['table']);
        });

        $this->app->extend(WorkCommand::class, fn ($command, $application): SafeQueueWorkCommand => new SafeQueueWorkCommand($application['queue.worker'], $application['cache.store']));
    }

    public function boot(): void
    {
        $this->app->afterResolving('mail.manager', function (MailManager $manager): void {
            // MailManager resolves nested failover/roundrobin transports through the same creator.
            $manager->extend('log', function (array $configuration): LogTransport {
                app(MailLoggingPolicy::class)->enforce($this->app);

                return new LogTransport($this->app['log']->channel('local-mail'));
            });
        });
    }
}
