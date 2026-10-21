<?php

namespace App\Console\Commands;

use App\Actions\Maintenance\PruneRetainedRecords;
use App\Enums\RetentionCategory;
use Illuminate\Console\Command;
use Throwable;

class PruneRetainedRecordsCommand extends Command
{
    protected $signature = 'retention:prune {--only=* : Restrict to named categories} {--execute : Delete eligible records in bounded batches}';

    protected $description = 'Preview or prune retained records without exposing identifiers or payloads';

    public function handle(PruneRetainedRecords $action): int
    {
        $categories = [];
        foreach ($this->option('only') as $name) {
            $category = RetentionCategory::tryFrom($name);
            if ($category === null) {
                $this->error('Unknown retention category. Use audit, oauth, codes, sessions, resets or failed-jobs.');

                return self::FAILURE;
            }
            $categories[$name] = $category;
        }
        try {
            $reports = $action->handle($categories === [] ? RetentionCategory::cases() : array_values($categories), (bool) $this->option('execute'));
            $this->info($this->option('execute') ? 'Bounded retention cleanup completed.' : 'Preview only. No records or checkpoints changed.');
            $this->table(['Category', 'UTC cutoff', 'Scanned', 'Eligible', 'Deleted', 'Invalid', 'Deferred'],
                collect($reports)->map(fn (array $report, string $category): array => [$category, ...array_values($report)])->all());
            $this->comment('Counts cover this bounded scan, not the whole database. Later runs continue from the execution checkpoint.');

            return self::SUCCESS;
        } catch (Throwable $exception) {
            report($exception);
            $this->error('Retention cleanup could not complete. Check safe diagnostics; earlier batches may already have committed.');

            return self::FAILURE;
        }
    }
}
