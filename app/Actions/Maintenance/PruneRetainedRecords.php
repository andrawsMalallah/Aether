<?php

namespace App\Actions\Maintenance;

use App\Enums\RetentionCategory;
use Carbon\CarbonImmutable;
use DateTimeImmutable;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use RuntimeException;

class PruneRetainedRecords
{
    public function __construct(private PruneOAuthCredentials $credentials) {}

    /**
     * @param  list<RetentionCategory>  $categories
     * @return array<string, array{cutoff: string, scanned: int, eligible: int, deleted: int, invalid: int, deferred: int}>
     */
    public function handle(array $categories, bool $execute = false): array
    {
        $this->validate($categories);
        $lock = $execute ? Cache::lock('retention:prune', 600) : null;
        if ($lock !== null && ! $lock->get()) {
            throw new RuntimeException('Retention cleanup is already running.');
        }
        try {
            $now = CarbonImmutable::now();
            $reports = [];
            foreach ($categories as $category) {
                $reports[$category->value] = $this->prune($category, $now, $execute);
            }

            return $reports;
        } finally {
            $lock?->release();
        }
    }

    /** @param list<RetentionCategory> $categories */
    private function validate(array $categories): void
    {
        foreach (['audit_days', 'credential_days', 'failed_job_days', 'scan_limit', 'delete_limit', 'family_limit'] as $setting) {
            $value = config('retention.'.$setting);
            if (! is_int($value) || $value < 1 || $value > 5000) {
                throw new RuntimeException('Retention configuration is invalid.');
            }
        }
        $connection = config('database.default');
        if (in_array(RetentionCategory::Sessions, $categories, true)
            && (config('session.driver') !== 'database' || (config('session.connection') ?? $connection) !== $connection
                || config('session.table', 'sessions') !== 'sessions' || ! is_int(config('session.lifetime')) || config('session.lifetime') < 1)) {
            throw new RuntimeException('Retention requires the supported database session store.');
        }
        if (in_array(RetentionCategory::Resets, $categories, true)) {
            $broker = config('auth.defaults.passwords');
            $settings = config('auth.passwords.'.$broker);
            if (($settings['driver'] ?? 'database') !== 'database' || ($settings['connection'] ?? $connection) !== $connection
                || ($settings['table'] ?? null) !== 'password_reset_tokens' || ! is_int($settings['expire'] ?? null) || $settings['expire'] < 1) {
                throw new RuntimeException('Retention requires the supported database reset store.');
            }
        }
        if (in_array(RetentionCategory::FailedJobs, $categories, true)
            && (config('queue.failed.driver') !== 'database-uuids' || (config('queue.failed.database') ?? $connection) !== $connection
                || config('queue.failed.table') !== 'failed_jobs')) {
            throw new RuntimeException('Retention requires the supported failed job store.');
        }
    }

    /** @return array{cutoff: string, scanned: int, eligible: int, deleted: int, invalid: int, deferred: int} */
    private function prune(RetentionCategory $category, CarbonImmutable $now, bool $execute): array
    {
        $cutoff = match ($category) {
            RetentionCategory::Audit => $now->subDays(config('retention.audit_days')),
            RetentionCategory::OAuth, RetentionCategory::Codes => $now->subDays(config('retention.credential_days')),
            RetentionCategory::FailedJobs => $now->subDays(config('retention.failed_job_days')),
            RetentionCategory::Sessions => $now->subMinutes(config('session.lifetime')),
            RetentionCategory::Resets => $now->subMinutes(config('auth.passwords.'.config('auth.defaults.passwords').'.expire')),
        };
        $report = ['cutoff' => $cutoff->toIso8601String(), 'scanned' => 0, 'eligible' => 0, 'deleted' => 0, 'invalid' => 0, 'deferred' => 0];
        $checkpoint = 'retention:cursor:'.hash('sha256', DB::connection()->getDatabaseName().':'.$category->value);
        $stored = Cache::get($checkpoint);
        $after = $stored === null ? null : Crypt::decryptString($stored);
        $query = DB::table($category->table())->select([$category->key(), $category->timestamp(),
            ...($category === RetentionCategory::OAuth ? ['client_id', 'user_id', 'auth_code_id'] : []),
            ...($category === RetentionCategory::Codes ? ['client_id', 'user_id'] : []),
        ])->orderBy($category->key());
        if ($after !== null) {
            $query->where($category->key(), '>', $after);
        }
        // Primary-key pagination bounds work even where a timestamp-only index does
        // not exist. Persist an encrypted cursor so retained rows cannot starve cleanup.
        $rows = $query->limit(config('retention.scan_limit'))->get();
        $last = null;
        $families = [];
        $genericKeys = [];
        foreach ($rows as $row) {
            if ($report['eligible'] >= config('retention.delete_limit')) {
                break;
            }
            $previous = $last;
            $last = (string) $row->{$category->key()};
            $report['scanned']++;
            $timestamp = $row->{$category->timestamp()};
            $date = is_string($timestamp) ? DateTimeImmutable::createFromFormat('!Y-m-d H:i:s', $timestamp) : false;
            if ($timestamp === null || ($category !== RetentionCategory::Sessions
                && ($date === false || $date->getTimestamp() < 0 || $date->format('Y-m-d H:i:s') !== $timestamp))) {
                $report['invalid']++;

                continue;
            }
            if ($timestamp >= ($category === RetentionCategory::Sessions ? $cutoff->timestamp : $cutoff->toDateTimeString())) {
                continue;
            }
            if (in_array($category, [RetentionCategory::OAuth, RetentionCategory::Codes], true)) {
                if ($category === RetentionCategory::OAuth) {
                    $lineage = $row->auth_code_id;
                    $family = json_encode([$row->client_id, $row->user_id, $lineage === null || trim($lineage) === '' ? $row->id : $lineage], JSON_THROW_ON_ERROR);
                    if (isset($families[$family])) {
                        continue;
                    }
                    if (count($families) >= config('retention.family_limit')) {
                        // Do not advance past an unexamined family.
                        $last = $previous;
                        break;
                    }
                    $families[$family] = true;
                }
                $result = $this->credentials->handle($row, $cutoff, $execute, config('retention.delete_limit') - $report['eligible'], $category === RetentionCategory::Codes);
                foreach (['eligible', 'deleted', 'invalid', 'deferred'] as $counter) {
                    $report[$counter] += $result[$counter];
                }
            } else {
                $report['eligible']++;
                $genericKeys[] = $last;
            }
        }
        if ($execute) {
            foreach (array_chunk($genericKeys, 100) as $keys) {
                // Recheck expiry in each bounded DELETE: a renewed session/reset
                // record between the scan and mutation must remain available.
                $report['deleted'] += $this->expired(DB::table($category->table())->whereIn($category->key(), $keys), $category, $cutoff)->delete();
            }
            if ($rows->isEmpty()) {
                Cache::forget($checkpoint);
            } elseif ($last !== null) {
                Cache::put($checkpoint, Crypt::encryptString($last), now()->addDays(30));
            }
        }

        return $report;
    }

    private function expired(Builder $query, RetentionCategory $category, CarbonImmutable $cutoff): Builder
    {
        return $query->where($category->timestamp(), '<', $category === RetentionCategory::Sessions ? $cutoff->timestamp : $cutoff);
    }
}
