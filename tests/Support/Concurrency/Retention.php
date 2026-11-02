<?php

namespace Tests\Support\Concurrency;

use App\Actions\Maintenance\PruneOAuthCredentials;
use App\Actions\Maintenance\PruneRetainedRecords;
use App\Enums\OAuthClientStatus;
use App\Enums\RetentionCategory;
use App\Models\OAuthClient;
use App\Models\User;
use App\Services\OAuth\ReadToken;
use Carbon\CarbonImmutable;
use Illuminate\Cache\RateLimiter;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Date;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use RuntimeException;

final class Retention
{
    private const TABLES = ['users', 'oauth_clients', 'consents', 'oauth_auth_codes', 'oauth_access_tokens', 'oauth_refresh_tokens', 'audit_logs', 'sessions', 'password_reset_tokens', 'failed_jobs', 'jobs', 'account_exports'];

    /** @param array<string, mixed> $configuration */
    public static function configure(array $configuration): void
    {
        Bootstrap::guard(DB::connection()->getPdo(), $configuration['run_id']);
        if (! preg_match('/^[a-zA-Z0-9_-]{1,80}$/D', $configuration['retention_scope'] ?? '')) {
            throw new RuntimeException('Invalid retention test scope.');
        }
        Date::setTestNow($configuration['test_now']);
        CarbonImmutable::setTestNow($configuration['test_now']);
        config(['cache.default' => 'database', 'cache.prefix' => 'retention-'.$configuration['run_id'].'-'.$configuration['retention_scope'].'-',
            'cache.stores.database.connection' => 'pgsql', 'cache.stores.database.lock_connection' => 'pgsql',
            'cache.stores.database.table' => 'cache', 'cache.stores.database.lock_table' => 'cache_locks',
            'queue.failed.driver' => 'database-uuids', 'queue.failed.database' => 'pgsql', 'queue.failed.table' => 'failed_jobs',
            'retention.scan_limit' => 1000, 'retention.delete_limit' => 1000, 'retention.family_limit' => 20]);
        $previousLimiter = app(RateLimiter::class);
        Cache::purge('database');
        // RateLimiter retains its constructor store; isolate each coordinator scenario
        // just like each fresh worker application, without disabling any real limiter.
        $limiter = new RateLimiter(Cache::store('database'));
        foreach (['two-factor', 'password-confirmation', 'two-factor-settings', 'login', 'registration', 'forgot-password',
            'reset-password', 'verification', 'account-changes', 'oidc-userinfo', 'oauth-authorize', 'oauth-token', 'oauth-revoke', 'oauth-introspect'] as $name) {
            $definition = $previousLimiter->limiter($name);
            self::check($definition !== null, 'Expected application rate limiter missing.');
            $limiter->for($name, $definition);
        }
        app()->instance(RateLimiter::class, $limiter);
        \Illuminate\Support\Facades\RateLimiter::clearResolvedInstance(RateLimiter::class);
        self::check(app()->environment('testing') && config('cache.default') === 'database'
            && config('retention.scheduled_enabled') === false, 'Unsafe retention test configuration.');
    }

    public static function check(bool $condition, string $reason): void
    {
        if (! $condition) {
            throw new RuntimeException($reason);
        }
    }

    /** @return array<string, int> */
    public static function counts(): array
    {
        $counts = [];
        foreach (self::TABLES as $table) {
            $counts[$table] = DB::table($table)->count();
        }
        self::check($counts['users'] <= 500 && $counts['oauth_clients'] <= 500 && array_sum($counts) <= 60000, 'Fixture budget exceeded.');

        return $counts;
    }

    /** @return array<string, string> */
    public static function snapshot(): array
    {
        $snapshot = [];
        foreach ([...self::TABLES, 'cache'] as $table) {
            $key = $table === 'password_reset_tokens' ? 'email' : ($table === 'cache' ? 'key' : 'id');
            $digest = hash_init('sha256');
            foreach (DB::table($table)->orderBy($key)->cursor() as $row) {
                hash_update($digest, json_encode($row, JSON_THROW_ON_ERROR));
            }
            $snapshot[$table] = hash_final($digest);
        }

        return $snapshot;
    }

    /** @return array{access: string, refresh: string, family: string} */
    public static function expired(string $client, ?int $user, ?string $family = null, int $refreshCount = 1): array
    {
        self::counts();
        $access = '000'.Str::random(77);
        $family ??= Str::random(80);
        DB::table('oauth_access_tokens')->insert(['id' => $access, 'client_id' => $client, 'user_id' => $user,
            'auth_code_id' => $family, 'scopes' => '[]', 'revoked' => true, 'expires_at' => now()->subDays(31)]);
        $refresh = '';
        for ($index = 0; $index < $refreshCount; $index++) {
            $refresh = Str::random(80);
            DB::table('oauth_refresh_tokens')->insert(['id' => $refresh, 'access_token_id' => $access,
                'revoked' => true, 'expires_at' => now()->subDays(31)]);
        }

        return compact('access', 'refresh', 'family');
    }

    /** @return array<string, mixed> */
    public static function prune(string $category = 'oauth', bool $execute = true): array
    {
        return app(PruneRetainedRecords::class)->handle([RetentionCategory::from($category)], $execute);
    }

    public static function cursor(string $category): string
    {
        return 'retention:cursor:'.hash('sha256', DB::connection()->getDatabaseName().':'.$category);
    }

    /** @param array<string, mixed> $input
     * @return array<string, mixed>
     */
    public static function work(array $input): array
    {
        if ($input['retention_op'] === 'hold_row') {
            DB::transaction(fn () => OAuthClient::whereKey($input['client_id'])->lockForUpdate()->firstOrFail());

            return ['status' => 200];
        }
        if ($input['retention_op'] === 'renew') {
            $table = $input['category'] === 'sessions' ? 'sessions' : 'password_reset_tokens';
            $key = $table === 'sessions' ? 'id' : 'email';
            $column = $table === 'sessions' ? 'last_activity' : 'created_at';
            $affected = DB::transaction(fn (): int => DB::table($table)->where($key, $input['identifier'])
                ->update([$column => $table === 'sessions' ? now()->timestamp : now()->toDateTimeString()]));

            return ['status' => 200, 'affected' => $affected];
        }
        if ($input['retention_op'] === 'hold_cache') {
            $lock = Cache::lock('retention:prune', 600);
            self::check($lock->get(), 'Cannot acquire fixture execution lock.');
            try {
                \concurrencyEvent(['type' => 'paused', 'worker' => $input['worker']]);
                $command = json_decode((string) fgets(STDIN), true, flags: JSON_THROW_ON_ERROR);
                self::check(($command['release'] ?? null) === $input['worker'], 'Invalid cache-lock release.');
            } finally {
                $lock->release();
            }

            return ['status' => 200];
        }
        self::check($input['retention_op'] === 'prune', 'Unknown retention worker operation.');
        $code = Artisan::call('retention:prune', ['--only' => [$input['category']], '--execute' => true]);
        $output = Artisan::output();

        return ['status' => $code === 0 ? 200 : 409, 'fixed_failure' => str_contains($output, 'Retention cleanup could not complete.')];
    }

    /** @param array<string, mixed> $configuration
     * @return array<string, mixed>
     */
    public static function race(array $configuration, string $case, bool $pruneFirst): array
    {
        $name = $case.($pruneFirst ? '-prune-first' : '-operation-first');
        $configuration['retention_scope'] = $name.'-'.Str::random(8);
        self::configure($configuration);
        if (in_array($case, ['R11', 'R12'], true)) {
            return self::renewalRace($configuration, $case, $name, $pruneFirst);
        }
        $lifecycle = ['R05' => 'rotate', 'R06' => 'disconnect', 'R07' => 'suspend', 'R08' => 'delete'][$case] ?? null;
        $pending = null;
        if ($lifecycle !== null) {
            [$fixture, $target, $actor, $consent, $pending, $userIds, $clientIds] = \lifecycleFixture($configuration, 'refresh', $lifecycle);
            $operation = ['lifecycle' => $lifecycle, 'actor_id' => $actor->id, 'client_id' => $fixture['client_id'], 'consent_id' => $consent->id];
        } else {
            $fixture = \concurrencyFixture($configuration, in_array($case, ['R03', 'R04'], true), false);
            $userIds = [$fixture['user_id']];
            $clientIds = [$fixture['client_id']];
            if ($case === 'R02') {
                $successor = \concurrencyIssue([...$fixture['credentials'], 'grant_type' => 'refresh_token', 'refresh_token' => $fixture['tokens']['refresh_token'], 'scope' => 'openid']);
                self::check(\concurrencyBearerValid($successor['access_token']), 'Replay successor fixture invalid.');
            }
            $action = ['R01' => 'refresh', 'R02' => 'refresh', 'R03' => 'code', 'R04' => 'code', 'R09' => 'revoke_access', 'R10' => 'revoke_refresh'][$case];
            $operation = \concurrencyAction($fixture, $action, false);
        }
        $family = in_array($case, ['R01', 'R02'], true) ? $fixture['family'] : null;
        $old = self::expired($fixture['client_id'], (int) $fixture['user_id'], $family);
        $category = $case === 'R04' ? 'codes' : 'oauth';
        $oldCode = null;
        if ($case === 'R04') {
            $oldCode = '000'.Str::random(77);
            DB::table('oauth_auth_codes')->insert(['id' => $oldCode, 'client_id' => $fixture['client_id'], 'user_id' => $fixture['user_id'],
                'scopes' => '[]', 'revoked' => true, 'expires_at' => now()->subDays(31)]);
        }
        $table = $case === 'R08' ? 'users' : 'oauth_clients';
        $identifier = $case === 'R08' ? $fixture['user_id'] : $fixture['client_id'];
        $gate = ['table' => $table, 'operation' => 'select', 'identifier' => $identifier];
        $operation['gate'] = $gate;
        $prune = ['retention_op' => 'prune', 'category' => $category, 'gate' => $gate];
        $before = \lifecycleAudits($userIds, $clientIds);
        [$pruneResult, $operationResult, $wait] = self::pair($configuration, $prune, $operation, $pruneFirst, $table);
        $checks = ['prune_success' => $pruneResult['status'] === 200,
            'operation_success' => $operationResult['status'] === ($case === 'R02' ? 400 : 200),
            'no_database_errors' => $pruneResult['database_errors'] === [] && $operationResult['database_errors'] === [],
            'no_open_transactions' => $pruneResult['transaction_level'] === 0 && $operationResult['transaction_level'] === 0,
            'old_family_policy' => in_array($case, ['R01', 'R02'], true)
                ? DB::table('oauth_access_tokens')->where('id', $old['access'])->exists()
                    && DB::table('oauth_refresh_tokens')->where('id', $old['refresh'])->exists()
                : ($category === 'codes' ? ! DB::table('oauth_auth_codes')->where('id', $oldCode)->exists()
                    : ! DB::table('oauth_access_tokens')->where('id', $old['access'])->exists()
                        && ! DB::table('oauth_refresh_tokens')->where('id', $old['refresh'])->exists())];
        $expectedSentinels = match ($lifecycle) {
            'rotate', 'suspend' => [false, false, true, true], 'disconnect' => [false, true, true, true],
            'delete' => [false, true, false, true], default => [true, true, true],
        };
        $checks['sentinels'] = array_map('concurrencyBearerValid', $fixture['sentinels']) === $expectedSentinels;
        $sentinelRefresh = array_map(function (string $token): bool {
            return Passport::refreshToken()->newQuery()->where('access_token_id', app(ReadToken::class)->access($token))->where('revoked', false)->exists();
        }, $fixture['sentinels']);
        $checks['sentinel_refresh'] = $sentinelRefresh === $expectedSentinels;
        $access = DB::table('oauth_access_tokens')->where('auth_code_id', $fixture['family'])->where('client_id', $fixture['client_id'])->where('user_id', $fixture['user_id']);
        $activeAccess = (clone $access)->where('revoked', false)->count();
        $activeRefresh = DB::table('oauth_refresh_tokens')->whereIn('access_token_id', (clone $access)->select('id'))->where('revoked', false)->count();
        $checks['family_result'] = $activeAccess === ($lifecycle === null && $case !== 'R02' && ! in_array($case, ['R09', 'R10'], true) ? 1 : 0)
            && $activeRefresh === ($lifecycle === null && $case !== 'R02' && ! in_array($case, ['R09', 'R10'], true) ? 1 : 0);
        $audits = \lifecycleAudits($userIds, $clientIds);
        foreach ($before as $event => $count) {
            $audits[$event] = ($audits[$event] ?? 0) - $count;
        }
        $event = match ($case) {
            'R01' => 'token.refreshed', 'R02' => 'refresh.replayed', 'R03', 'R04' => 'token.issued',
            'R05' => 'client.secret_regenerated', 'R06' => 'consent.revoked', 'R07' => 'client.suspended',
            'R08' => 'account.deletion_requested', default => 'token.revoked',
        };
        $checks['audit'] = ($audits[$event] ?? 0) === 1;
        if (in_array($case, ['R01', 'R03', 'R04'], true)) {
            $checks['identity'] = $operationResult['identity_valid'] === true;
        }
        if ($case === 'R02') {
            $checks['replay_rejected'] = $operationResult['oauth_error'] === 'invalid_grant';
        }
        if ($lifecycle !== null) {
            $client = OAuthClient::findOrFail($fixture['client_id']);
            $checks['lifecycle_state'] = match ($lifecycle) {
                'rotate' => ! Hash::check($fixture['credentials']['client_secret'], $client->secret),
                'disconnect' => $consent->fresh()->revoked_at !== null,
                'suspend' => $client->status === OAuthClientStatus::Suspended,
                'delete' => $target->fresh()->deletion_requested_at !== null,
            };
            $response = Bootstrap::request(app(), '/oauth/token', $pending['data']);
            $checks['pending_code_rejected'] = in_array($response->getStatusCode(), [400, 401], true);
        }
        self::counts();

        return ['scenario' => $name, 'classification' => ! in_array(false, $checks, true) ? 'passed' : 'needs_review',
            'checks' => $checks, 'lock_wait' => $wait, 'prune' => $pruneResult, 'operation' => $operationResult];
    }

    /** @param array<string, mixed> $configuration
     * @param  array<string, mixed>  $prune
     * @param  array<string, mixed>  $operation
     * @return array{array<string, mixed>, array<string, mixed>, array<string, mixed>}
     */
    private static function pair(array $configuration, array $prune, array $operation, bool $pruneFirst, string $table, bool $ordered = false): array
    {
        [$firstInput, $secondInput] = $pruneFirst ? [$prune, $operation] : [$operation, $prune];
        $first = $second = null;
        try {
            $first = new WorkerProcess(['configuration' => $configuration, 'worker' => 'first', ...$firstInput]);
            $firstReady = $first->await('ready');
            $first->await('paused');
            if ($ordered) {
                $first->send(['release' => 'first']);
                $firstResult = $first->await('result');
            }
            $second = new WorkerProcess(['configuration' => $configuration, 'worker' => 'second', ...$secondInput]);
            $secondReady = $second->await('ready');
            $wait = ['observed' => false, 'requested_table' => null, 'ordered_without_wait' => $ordered];
            if (! $ordered) {
                $deadline = microtime(true) + 5;
                do {
                    $wait = self::wait((int) $secondReady['connection'], (int) $firstReady['connection'], $table);
                    if ($wait['observed']) {
                        break;
                    }
                    $second->pump();
                    usleep(10000);
                } while (microtime(true) < $deadline);
                $first->send(['release' => 'first']);
                $firstResult = $first->await('result');
            }
            $deadline = microtime(true) + 20;
            while ($second->event('result') === null) {
                if ($second->event('paused') !== null) {
                    $second->send(['release' => 'second']);
                    break;
                }
                self::check(microtime(true) < $deadline, 'Retention second-worker timeout.');
                usleep(10000);
            }
            $secondResult = $second->await('result');
            self::check($ordered || $wait['observed'] && $wait['requested_table'] === $table, 'Required retention lock wait missing.');

            return $pruneFirst ? [$firstResult, $secondResult, $wait] : [$secondResult, $firstResult, $wait];
        } finally {
            $first?->close();
            $second?->close();
        }
    }

    /** @return array<string, mixed> */
    private static function wait(int $requester, int $blocker, string $table): array
    {
        $row = DB::selectOne('SELECT EXISTS (SELECT 1 FROM pg_stat_activity a JOIN pg_locks l ON l.pid = a.pid JOIN pg_class c ON c.oid = l.relation WHERE a.pid = ? AND ?::integer = ANY(pg_blocking_pids(a.pid)) AND a.datname = current_database() AND c.relname = ? AND position(quote_ident(c.relname) in a.query) > 0) AS observed', [$requester, $blocker, $table]);

        return ['observed' => (bool) $row->observed, 'requested_table' => $row->observed ? $table : null, 'ordered_without_wait' => false];
    }

    /** @param array<string, mixed> $configuration
     * @return array<string, mixed>
     */
    private static function renewalRace(array $configuration, string $case, string $name, bool $pruneFirst): array
    {
        $session = $case === 'R11';
        $category = $session ? 'sessions' : 'resets';
        $table = $session ? 'sessions' : 'password_reset_tokens';
        $key = $session ? 'id' : 'email';
        // Keep this contested row inside the first bounded page even when a
        // retained fixture already contains the larger query-plan distributions.
        $identifier = '000-retention-'.Str::uuid().($session ? '' : '@example.test');
        DB::table($table)->insert($session ? ['id' => $identifier, 'payload' => 'synthetic', 'last_activity' => now()->subHours(3)->timestamp]
            : ['email' => $identifier, 'token' => 'synthetic', 'created_at' => now()->subHours(2)]);
        $prune = ['retention_op' => 'prune', 'category' => $category, 'gate' => ['table' => $table, 'operation' => 'delete', 'identifier' => $identifier]];
        $renew = ['retention_op' => 'renew', 'category' => $category, 'identifier' => $identifier,
            'gate' => ['table' => $table, 'operation' => 'update', 'identifier' => $identifier]];
        [$pruneResult, $renewResult, $wait] = self::pair($configuration, $prune, $renew, $pruneFirst, $table, $pruneFirst);
        $row = DB::table($table)->where($key, $identifier)->first();
        $checks = ['prune_success' => $pruneResult['status'] === 200, 'renew_success' => $renewResult['status'] === 200,
            'outcome' => $pruneFirst ? $row === null && $renewResult['affected'] === 0
                : $row !== null && $renewResult['affected'] === 1 && ($session ? $row->last_activity === now()->timestamp : $row->created_at === now()->toDateTimeString()),
            'no_database_errors' => $pruneResult['database_errors'] === [] && $renewResult['database_errors'] === []];

        return ['scenario' => $name, 'classification' => ! in_array(false, $checks, true) ? 'passed' : 'needs_review', 'checks' => $checks, 'lock_wait' => $wait];
    }

    /** @param array<string, mixed> $configuration
     * @return array<string, mixed>
     */
    public static function plans(array $configuration): array
    {
        $configuration['retention_scope'] = 'plans-'.Str::random(8);
        self::configure($configuration);
        self::check(array_sum(self::counts()) + 24000 <= 60000, 'Insufficient query-plan fixture budget.');
        $fixture = \concurrencyFixture($configuration, false, false);
        $namespace = Str::uuid();
        $rows = [];
        $refreshRows = [];
        for ($index = 0; $index < 5000; $index++) {
            $access = substr(hash('sha512', $namespace.'access'.$index), 0, 80);
            $family = substr(hash('sha512', $namespace.($index < 1000 ? 'large-live' : ($index < 1200 ? 'large-expired' : 'family'.$index))), 0, 80);
            $expiry = $index === 0 ? now()->subDays(31) : ($index < 1000 ? now()->addHour() : ($index < 1200 ? now()->subDays(31)
                : ($index % 4 === 0 ? now()->addHour() : ($index % 11 === 0 ? null : now()->subDays(31)))));
            $rows[] = ['id' => $access, 'client_id' => $fixture['client_id'], 'user_id' => $fixture['user_id'],
                'auth_code_id' => $family, 'scopes' => '[]', 'revoked' => true, 'expires_at' => $expiry];
            foreach ([0, 1] as $child) {
                $refreshRows[] = ['id' => substr(hash('sha512', $namespace.'refresh'.$index.'-'.$child), 0, 80),
                    'access_token_id' => $access, 'revoked' => true, 'expires_at' => $expiry];
            }
            if (count($rows) === 250) {
                DB::table('oauth_access_tokens')->insert($rows);
                DB::table('oauth_refresh_tokens')->insert($refreshRows);
                $rows = $refreshRows = [];
            }
        }
        foreach (['audit_logs', 'sessions', 'password_reset_tokens', 'failed_jobs', 'oauth_auth_codes'] as $table) {
            $rows = [];
            for ($index = 0; $index < 1000; $index++) {
                $identifier = substr(hash('sha512', $namespace.$table.$index), 0, 80);
                $expired = $index % 2 === 0;
                $rows[] = match ($table) {
                    'audit_logs' => ['event' => 'login.failed', 'created_at' => $expired ? now()->subDays(366) : now()],
                    'sessions' => ['id' => $identifier, 'payload' => 'synthetic', 'last_activity' => ($expired ? now()->subHours(3) : now())->timestamp],
                    'password_reset_tokens' => ['email' => $identifier.'@example.test', 'token' => 'synthetic', 'created_at' => $expired ? now()->subHours(2) : now()],
                    'failed_jobs' => ['uuid' => (string) Str::uuid(), 'connection' => 'database', 'queue' => 'default', 'payload' => 'synthetic', 'exception' => 'synthetic', 'failed_at' => $expired ? now()->subDays(31) : now()],
                    'oauth_auth_codes' => ['id' => $identifier, 'client_id' => $fixture['client_id'], 'user_id' => $fixture['user_id'], 'scopes' => '[]', 'revoked' => true, 'expires_at' => $expired ? now()->subDays(31) : now()],
                };
                if (count($rows) === 250) {
                    DB::table($table)->insert($rows);
                    $rows = [];
                }
            }
        }
        foreach (['oauth_access_tokens', 'oauth_refresh_tokens', 'oauth_auth_codes', 'oauth_clients', 'users', 'audit_logs', 'sessions', 'password_reset_tokens', 'failed_jobs'] as $table) {
            // Names are from this fixed allowlist; fixture statistics never touch another DB.
            DB::statement('ANALYZE "'.$table.'"');
        }
        $queries = [];
        $capture = true;
        $sample = 'cleanup';
        DB::listen(function (QueryExecuted $query) use (&$capture, &$queries, &$sample): void {
            if ($capture && preg_match('/^(select|delete) /', $query->sql)
                && preg_match('/"(oauth_access_tokens|oauth_refresh_tokens|oauth_auth_codes|oauth_clients|users|audit_logs|sessions|password_reset_tokens|failed_jobs)"/', $query->sql)) {
                $queries[$sample.'.'.hash('sha256', $query->sql)] = ['sql' => $query->sql, 'bindings' => $query->bindings, 'sample' => $sample];
            }
        });
        // Capture DML in a rolled-back instrumentation transaction so subsequent
        // SELECT measurements still see the complete seeded distributions. This
        // wrapper is for plans only, never used by the race/atomicity assertions.
        DB::beginTransaction();
        try {
            foreach (['large-live' => 0, 'large-expired' => 1000, 'small-expired' => 1201] as $sample => $index) {
                $candidate = DB::table('oauth_access_tokens')->where('id', substr(hash('sha512', $namespace.'access'.$index), 0, 80))->first();
                app(PruneOAuthCredentials::class)->handle($candidate, CarbonImmutable::now()->subDays(30), false, 1000);
            }
            $sample = 'cleanup';
            app(PruneRetainedRecords::class)->handle(RetentionCategory::cases(), true);
        } finally {
            $capture = false;
            DB::rollBack();
        }
        DB::statement("SET statement_timeout = '5s'");
        $summaries = [];
        $cursorChecks = [];
        try {
            foreach (RetentionCategory::cases() as $category) {
                $base = DB::table($category->table())->select([$category->key(), $category->timestamp(),
                    ...($category === RetentionCategory::OAuth ? ['client_id', 'user_id', 'auth_code_id'] : []),
                    ...($category === RetentionCategory::Codes ? ['client_id', 'user_id'] : [])])->orderBy($category->key());
                foreach (['start' => 0, 'middle' => (int) (DB::table($category->table())->count() / 2), 'tail' => max(0, DB::table($category->table())->count() - 10)] as $position => $offset) {
                    $query = clone $base;
                    if ($position !== 'start') {
                        $after = DB::table($category->table())->orderBy($category->key())->offset($offset)->value($category->key());
                        $query->where($category->key(), '>', $after);
                    }
                    $query->limit(config('retention.scan_limit'));
                    $summary = self::explain($query->toSql(), $query->getBindings(), $category->value.'.cursor.'.$position, true);
                    $summaries[] = $summary;
                    $cursorChecks[] = $summary['root_type'] === 'Limit' && $summary['actual_rows'] <= config('retention.scan_limit');
                }
            }
            foreach ($queries as $shape => $query) {
                $readOnly = str_starts_with($query['sql'], 'select ') && ! str_contains($query['sql'], 'for update');
                $summaries[] = self::explain($query['sql'], $query['bindings'], $query['sample'].'.'.substr(hash('sha256', $shape), 0, 12), $readOnly);
            }
        } finally {
            DB::statement('SET statement_timeout = 0');
        }
        $checks = ['cursor_shapes' => count($cursorChecks) === 18 && ! in_array(false, $cursorChecks, true),
            'captured_shapes' => count($queries) >= 15, 'within_budget' => array_sum(self::counts()) <= 60000];

        return ['classification' => ! in_array(false, $checks, true) ? 'passed' : 'needs_review', 'checks' => $checks,
            'seeded_rows' => 20000, 'distributions' => ['large_live_family' => 1000, 'large_expired_family' => 200, 'independent_families' => 3800],
            'capture_rolled_back' => true, 'scope' => 'local_fixture_plan_evidence_not_production_scale', 'summaries' => $summaries];
    }

    /** @param array<int, mixed> $bindings
     * @return array<string, mixed>
     */
    public static function explain(string $sql, array $bindings, string $label, bool $measure): array
    {
        self::check(! $measure || str_starts_with($sql, 'select ') && ! str_contains($sql, 'for update'), 'Unsafe measured plan refused.');
        $raw = DB::selectOne('EXPLAIN ('.($measure ? 'ANALYZE, BUFFERS, ' : '').'FORMAT JSON) '.$sql, $bindings);
        $plan = json_decode($raw->{'QUERY PLAN'}, true, flags: JSON_THROW_ON_ERROR)[0];
        $nodes = [];
        $visit = function (array $node) use (&$visit, &$nodes): void {
            // Do not retain Filter/Index Cond/Output: they can contain credential constants.
            $nodes[] = array_intersect_key($node, array_flip(['Node Type', 'Relation Name', 'Index Name', 'Plan Rows', 'Actual Rows', 'Actual Loops',
                'Rows Removed by Filter', 'Shared Hit Blocks', 'Shared Read Blocks', 'Heap Fetches', 'Sort Method', 'Sort Space Used']));
            foreach ($node['Plans'] ?? [] as $child) {
                $visit($child);
            }
        };
        $visit($plan['Plan']);

        return ['label' => $label, 'measured_select' => $measure, 'root_type' => $plan['Plan']['Node Type'],
            'actual_rows' => $plan['Plan']['Actual Rows'] ?? null, 'execution_ms' => $plan['Execution Time'] ?? null,
            'planning_ms' => $plan['Planning Time'] ?? null, 'nodes' => $nodes];
    }

    /** @param callable(): mixed $operation
     * @return array{injected: bool, inside_transaction: bool}
     */
    private static function inject(string $table, string $identifier, callable $operation, string $operationName = 'delete'): array
    {
        $active = true;
        $injected = $transaction = false;
        DB::listen(function (QueryExecuted $query) use (&$active, &$injected, &$transaction, $table, $identifier, $operationName): void {
            if ($active && str_starts_with($query->sql, $operationName.' ') && str_contains($query->sql, '"'.$table.'"') && in_array($identifier, $query->bindings, true)) {
                $injected = true;
                $transaction = DB::transactionLevel() > 0;
                throw new RetentionInjectedFailure;
            }
        });
        try {
            $operation();
        } catch (RetentionInjectedFailure) {
            // Deliberate post-mutation failure must escape the actual family transaction.
        } finally {
            $active = false;
        }

        return ['injected' => $injected, 'inside_transaction' => $transaction];
    }

    /** @param array<string, mixed> $configuration
     * @return array<string, mixed>
     */
    public static function control(array $configuration, string $case): array
    {
        $configuration['retention_scope'] = $case.'-'.Str::random(8);
        self::configure($configuration);
        $fixture = \concurrencyFixture($configuration, false, false);
        $old = self::expired($fixture['client_id'], (int) $fixture['user_id']);
        $checks = [];
        if ($case === 'C01') {
            $suffix = Str::uuid();
            DB::table('audit_logs')->insert(['event' => 'login.failed', 'created_at' => now()->subDays(366)]);
            DB::table('sessions')->insert(['id' => 'preview-'.$suffix, 'payload' => 'synthetic', 'last_activity' => now()->subHours(3)->timestamp]);
            DB::table('password_reset_tokens')->insert(['email' => 'preview-'.$suffix.'@example.test', 'token' => 'synthetic', 'created_at' => now()->subHours(2)]);
            DB::table('failed_jobs')->insert(['uuid' => Str::uuid(), 'connection' => 'database', 'queue' => 'default', 'payload' => 'synthetic', 'exception' => 'synthetic', 'failed_at' => now()->subDays(31)]);
            DB::table('oauth_auth_codes')->insert(['id' => '000'.Str::random(77), 'client_id' => $fixture['client_id'], 'user_id' => $fixture['user_id'], 'scopes' => '[]', 'revoked' => true, 'expires_at' => now()->subDays(31)]);
            $holder = new WorkerProcess(['configuration' => $configuration, 'worker' => 'holder', 'retention_op' => 'hold_row', 'client_id' => $fixture['client_id'],
                'gate' => ['table' => 'oauth_clients', 'operation' => 'select', 'identifier' => $fixture['client_id']]]);
            try {
                $holder->await('ready');
                $holder->await('paused');
                $before = self::snapshot();
                $report = app(PruneRetainedRecords::class)->handle(RetentionCategory::cases());
                $checks = ['all_categories' => count($report) === 6 && collect($report)->every(fn (array $row): bool => $row['deleted'] === 0 && $row['eligible'] > 0),
                    'immutable' => self::snapshot() === $before,
                    'no_execution_lock' => ! DB::table('cache_locks')->where('key', 'like', config('cache.prefix').'%')->exists()];
                $holder->send(['release' => 'holder']);
                $checks['holder_success'] = $holder->await('result')['status'] === 200;
            } finally {
                $holder->close();
            }
        } elseif ($case === 'C02') {
            $holder = new WorkerProcess(['configuration' => $configuration, 'worker' => 'holder', 'retention_op' => 'hold_cache',
                'gate' => ['table' => 'users', 'operation' => 'select', 'identifier' => -1]]);
            $contender = null;
            try {
                $holder->await('ready');
                $holder->await('paused');
                $before = self::snapshot();
                $contender = new WorkerProcess(['configuration' => $configuration, 'worker' => 'contender', 'retention_op' => 'prune', 'category' => 'oauth',
                    'gate' => ['table' => 'users', 'operation' => 'select', 'identifier' => -1]]);
                $result = $contender->await('result');
                $checks = ['refused' => $result['status'] === 409 && $result['fixed_failure'], 'immutable' => self::snapshot() === $before];
                $holder->send(['release' => 'holder']);
                $checks['released'] = $holder->await('result')['status'] === 200;
            } finally {
                $holder->close();
                $contender?->close();
            }
        } elseif (in_array($case, ['C03', 'C04', 'C05'], true)) {
            self::prune();
            $old = self::expired($fixture['client_id'], (int) $fixture['user_id']);
            Cache::forget(self::cursor('oauth'));
            $before = self::snapshot();
            $failure = self::inject($case === 'C04' ? 'oauth_refresh_tokens' : 'oauth_access_tokens', $case === 'C04' ? $old['refresh'] : $old['access'],
                fn (): array => self::prune(), $case === 'C03' ? 'select' : 'delete');
            $checks = ['injected' => $failure['injected'], 'transaction' => $failure['inside_transaction'], 'rollback' => self::snapshot() === $before,
                'cursor_unchanged' => Cache::get(self::cursor('oauth')) === null, 'no_transaction' => DB::transactionLevel() === 0];
            $lock = Cache::lock('retention:prune', 600);
            $checks['execution_lock_released'] = $lock->get();
            if ($checks['execution_lock_released']) {
                $lock->release();
            }
            self::prune();
            $checks['retry_deleted'] = ! DB::table('oauth_access_tokens')->where('id', $old['access'])->exists();
        } elseif ($case === 'C06') {
            self::prune();
            $pairs = [self::expired($fixture['client_id'], (int) $fixture['user_id']), self::expired($fixture['client_id'], (int) $fixture['user_id'])];
            usort($pairs, fn (array $left, array $right): int => strcmp($left['access'], $right['access']));
            Cache::forget(self::cursor('oauth'));
            $failure = self::inject('oauth_refresh_tokens', $pairs[1]['refresh'], fn (): array => self::prune());
            $checks = ['injected' => $failure['injected'] && $failure['inside_transaction'],
                'earlier_commit' => ! DB::table('oauth_access_tokens')->where('id', $pairs[0]['access'])->exists(),
                'failing_family_restored' => DB::table('oauth_access_tokens')->where('id', $pairs[1]['access'])->exists() && DB::table('oauth_refresh_tokens')->where('id', $pairs[1]['refresh'])->exists(),
                'cursor_not_advanced' => Cache::get(self::cursor('oauth')) === null];
            self::prune();
            $checks['retry_converged'] = ! DB::table('oauth_access_tokens')->whereIn('id', array_column($pairs, 'access'))->exists();
        } elseif ($case === 'C07') {
            self::prune();
            $large = self::expired($fixture['client_id'], (int) $fixture['user_id'], refreshCount: 501);
            config(['retention.delete_limit' => 17]);
            Cache::forget(self::cursor('oauth'));
            $bounded = $backing = true;
            $runs = 0;
            do {
                $report = self::prune()['oauth'];
                $bounded = $bounded && $report['deleted'] <= 17 && $report['scanned'] <= 1000;
                $refreshRemain = DB::table('oauth_refresh_tokens')->where('access_token_id', $large['access'])->exists();
                $backing = $backing && (! $refreshRemain || DB::table('oauth_access_tokens')->where('id', $large['access'])->exists());
                $runs++;
            } while (DB::table('oauth_access_tokens')->where('id', $large['access'])->exists() && $runs < 100);
            $checks = ['bounded' => $bounded, 'backing_preserved' => $backing, 'multiple_batches' => $runs > 1 && $runs < 100,
                'converged' => ! DB::table('oauth_access_tokens')->where('id', $large['access'])->exists()];
        } elseif ($case === 'C08') {
            $after = DB::table('audit_logs')->max('id') ?? 0;
            $ids = [];
            foreach ([false, true, false, true, true] as $expired) {
                $ids[] = DB::table('audit_logs')->insertGetId(['event' => 'login.failed', 'created_at' => $expired ? now()->subDays(366) : now()]);
            }
            Cache::put(self::cursor('audit'), Crypt::encryptString((string) $after), 600);
            config(['retention.scan_limit' => 2, 'retention.delete_limit' => 1, 'retention.family_limit' => 1]);
            $bounded = true;
            for ($iteration = 0; $iteration < 4; $iteration++) {
                $report = self::prune('audit')['audit'];
                $bounded = $bounded && $report['scanned'] <= 2 && $report['deleted'] <= 1;
            }
            $checks = ['cursor_bounds' => $bounded, 'eligible_progress' => DB::table('audit_logs')->whereIn('id', $ids)->count() === 2];
            $families = [self::expired($fixture['client_id'], (int) $fixture['user_id']), self::expired($fixture['client_id'], (int) $fixture['user_id'])];
            config(['retention.delete_limit' => 10]);
            $familyBound = true;
            for ($iteration = 0; $iteration < 300; $iteration++) {
                $report = self::prune()['oauth'];
                $familyBound = $familyBound && $report['deleted'] <= 2 && $report['scanned'] <= 2;
                if (! DB::table('oauth_access_tokens')->whereIn('id', array_column($families, 'access'))->exists()) {
                    break;
                }
            }
            $checks['family_limit'] = $familyBound;
            $checks['family_convergence'] = $iteration < 300;
            for ($iteration = 0; $iteration < 1000 && Cache::get(self::cursor('oauth')) !== null; $iteration++) {
                self::prune();
            }
            $checks['cursor_wrap'] = Cache::get(self::cursor('oauth')) === null;
        } elseif ($case === 'C09') {
            self::prune();
            $unknown = self::expired($fixture['client_id'], (int) $fixture['user_id']);
            DB::table('oauth_refresh_tokens')->where('id', $unknown['refresh'])->update(['expires_at' => null]);
            $ambiguous = self::expired($fixture['client_id'], (int) $fixture['user_id']);
            DB::table('oauth_access_tokens')->where('id', $ambiguous['access'])->update(['auth_code_id' => ' ']);
            $valid = self::expired($fixture['client_id'], (int) $fixture['user_id']);
            $foreignClient = \concurrencyClient(false);
            $foreign = self::expired($foreignClient->id, (int) $fixture['user_id'], $valid['family']);
            DB::table('oauth_access_tokens')->where('id', $foreign['access'])->update(['expires_at' => now()->addHour(), 'revoked' => false]);
            $otherUser = User::create(['name' => 'Retention sentinel', 'email' => 'retention-'.Str::uuid().'@example.test', 'password' => Str::random(40)]);
            $foreignOwner = self::expired($fixture['client_id'], $otherUser->id, $valid['family']);
            DB::table('oauth_access_tokens')->where('id', $foreignOwner['access'])->update(['expires_at' => now()->addHour()]);
            $machine = app(ClientRepository::class)->createClientCredentialsGrantClient('Retention machine');
            $machinePair = self::expired($machine->id, null);
            DB::table('oauth_access_tokens')->where('id', $machinePair['access'])->update(['auth_code_id' => null]);
            Cache::forget(self::cursor('oauth'));
            self::prune();
            $checks = ['unknown_retained' => DB::table('oauth_refresh_tokens')->where('id', $unknown['refresh'])->exists(),
                'ambiguous_retained' => DB::table('oauth_access_tokens')->where('id', $ambiguous['access'])->exists(),
                'eligible_removed' => ! DB::table('oauth_access_tokens')->where('id', $valid['access'])->exists(),
                'foreign_client_retained' => DB::table('oauth_access_tokens')->where('id', $foreign['access'])->exists(),
                'foreign_owner_retained' => DB::table('oauth_access_tokens')->where('id', $foreignOwner['access'])->exists(),
                'machine_removed' => ! DB::table('oauth_access_tokens')->where('id', $machinePair['access'])->exists(),
                'live_sentinel' => \concurrencyBearerValid($fixture['tokens']['access_token'])];
        } elseif ($case === 'C10') {
            $marker = 'private-marker-'.Str::random(20);
            $code = Artisan::call('retention:prune', ['--only' => ['oauth'], '--execute' => true]);
            $output = Artisan::output();
            $cursor = Cache::get(self::cursor('oauth'));
            $checks = ['command_success' => $code === 0, 'aggregate_output' => str_contains($output, 'Bounded retention cleanup completed.')
                && ! str_contains($output, $fixture['client_id']) && ! str_contains($output, $fixture['tokens']['access_token']) && ! str_contains($output, $old['access']),
                'encrypted_cursor' => is_string($cursor) && Crypt::decryptString($cursor) !== $cursor,
                'invalid_category_nonzero' => Artisan::call('retention:prune', ['--only' => [$marker], '--execute' => true]) !== 0
                    && ! str_contains(Artisan::output(), $marker)];
        } else {
            throw new RuntimeException('Unknown retention control.');
        }
        $checks['sentinels'] = ! in_array(false, array_map('concurrencyBearerValid', $fixture['sentinels']), true);
        self::counts();

        return ['scenario' => $case, 'classification' => ! in_array(false, $checks, true) ? 'passed' : 'needs_review', 'checks' => $checks];
    }
}

final class RetentionInjectedFailure extends RuntimeException {}
