<?php

// Explicit fixture-only DDL experiment; never discovered by the application suite.
use App\Actions\Maintenance\PruneOAuthCredentials;
use Carbon\CarbonImmutable;
use Dotenv\Dotenv;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Encryption\Encrypter;
use Illuminate\Support\Facades\DB;
use phpseclib4\Crypt\RSA;
use Tests\Support\Concurrency\Bootstrap;
use Tests\Support\Concurrency\Retention;

require dirname(__DIR__, 2).'/vendor/autoload.php';
ini_set('display_errors', '0');
ini_set('log_errors', '0');

/** @return array<string, mixed> */
function retentionIndexInventory(): array
{
    $indexes = DB::select("SELECT c.relname AS name, t.relname AS table_name, i.indisvalid AS valid, pg_relation_size(c.oid) AS bytes, pg_get_indexdef(c.oid) AS definition FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid JOIN pg_class t ON t.oid = i.indrelid JOIN pg_namespace n ON n.oid = t.relnamespace WHERE n.nspname = 'public' AND t.relname IN ('oauth_access_tokens', 'oauth_refresh_tokens') ORDER BY c.relname");

    return ['database_bytes' => (int) DB::selectOne('SELECT pg_database_size(current_database()) AS bytes')->bytes,
        'indexes' => array_map(fn (object $row): array => ['name' => $row->name, 'table' => $row->table_name, 'valid' => (bool) $row->valid,
            'bytes' => (int) $row->bytes, 'definition' => $row->definition], $indexes)];
}

/** @return array<string, stdClass> */
function retentionIndexSamples(CarbonImmutable $cutoff): array
{
    $groups = DB::table('oauth_access_tokens')->whereNotNull('auth_code_id')->where('auth_code_id', '!=', '')
        ->whereNotNull('user_id')->groupBy('auth_code_id', 'client_id', 'user_id')
        ->selectRaw('auth_code_id, client_id, user_id, count(*) AS members, count(expires_at) AS known, min(expires_at) AS oldest, max(expires_at) AS newest')
        ->orderByDesc('members')->orderBy('auth_code_id')->get();
    $samples = [];
    foreach ($groups as $group) {
        $label = match (true) {
            (int) $group->members >= 100 && $group->oldest < $cutoff->toDateTimeString() && $group->newest >= $cutoff->toDateTimeString() => 'large-live',
            (int) $group->members >= 100 && (int) $group->known === (int) $group->members && $group->newest < $cutoff->toDateTimeString() => 'large-expired',
            (int) $group->members === 1 && (int) $group->known === 1 && $group->newest < $cutoff->toDateTimeString() => 'small-expired',
            default => null,
        };
        if ($label === null || isset($samples[$label])) {
            continue;
        }
        $candidate = DB::table('oauth_access_tokens')->where('auth_code_id', $group->auth_code_id)->where('client_id', $group->client_id)
            ->where('user_id', $group->user_id)->where('expires_at', '<', $cutoff)->orderBy('id')->first();
        if ($candidate !== null) {
            $samples[$label] = $candidate;
        }
    }
    $samples['unknown-expiry'] = DB::table('oauth_access_tokens')->whereNotNull('auth_code_id')->whereNotNull('user_id')->whereNull('expires_at')->orderBy('id')->first();
    Retention::check(count($samples) === 4 && ! in_array(null, $samples, true), 'Required retained sample distributions unavailable.');

    return $samples;
}

/** @param array<string, stdClass> $samples
 * @return array<string, array<string, mixed>>
 */
function retentionIndexQueries(array $samples, CarbonImmutable $cutoff): array
{
    $queries = [];
    $capturing = true;
    $label = '';
    DB::listen(function (QueryExecuted $query) use (&$queries, &$capturing, &$label): void {
        if ($capturing && str_starts_with($query->sql, 'select ')) {
            Retention::check(! str_contains($query->sql, 'for update'), 'Unexpected locking preview query.');
            $queries[$label.'.'.substr(hash('sha256', $query->sql), 0, 12)] = ['sql' => $query->sql, 'bindings' => $query->bindings, 'sample' => $label];
        }
    });
    try {
        foreach ($samples as $label => $candidate) {
            app(PruneOAuthCredentials::class)->handle($candidate, $cutoff, false, 2);
        }
    } finally {
        $capturing = false;
    }
    foreach (['start', 'middle', 'tail'] as $position) {
        $query = DB::table('oauth_access_tokens')->select(['id', 'expires_at', 'client_id', 'user_id', 'auth_code_id'])->orderBy('id')->limit(1000);
        if ($position !== 'start') {
            $count = DB::table('oauth_access_tokens')->count();
            $after = DB::table('oauth_access_tokens')->orderBy('id')->offset($position === 'middle' ? (int) ($count / 2) : max(0, $count - 10))->value('id');
            $query->where('id', '>', $after);
        }
        $queries['cursor.'.$position] = ['sql' => $query->toSql(), 'bindings' => $query->getBindings(), 'sample' => 'cursor'];
    }

    return $queries;
}

/** @param array<string, array<string, mixed>> $queries
 * @param  array<string, stdClass>  $samples
 * @return array<string, mixed>
 */
function retentionIndexMeasure(array $queries, array $samples, CarbonImmutable $cutoff): array
{
    $reports = [];
    foreach ($samples as $label => $candidate) {
        $reports[$label] = app(PruneOAuthCredentials::class)->handle($candidate, $cutoff, false, 2);
    }
    $measurements = [];
    foreach ($queries as $label => $query) {
        $rowsDigest = hash('sha256', json_encode(DB::select($query['sql'], $query['bindings']), JSON_THROW_ON_ERROR));
        $runs = [];
        for ($repeat = 0; $repeat < 5; $repeat++) {
            $runs[] = Retention::explain($query['sql'], $query['bindings'], $label, true);
        }
        $durations = array_column($runs, 'execution_ms');
        sort($durations);
        $plan = $runs[2];
        $plan['median_ms'] = $durations[2];
        $plan['result_sha256'] = $rowsDigest;
        $plan['kind'] = str_contains($query['sql'], 'select exists')
            ? (str_contains($query['sql'], '"oauth_refresh_tokens"') ? 'refresh-eligibility' : 'access-eligibility')
            : ($query['sample'] === 'cursor' ? 'cursor' : 'lookup');
        $measurements[$label] = $plan;
    }

    return ['preview_reports' => $reports, 'queries' => $measurements];
}

/** @param array<string, mixed> $stage */
function retentionIndexRefreshWorkRemains(array $stage): bool
{
    foreach ($stage['queries'] as $query) {
        if ($query['kind'] !== 'refresh-eligibility') {
            continue;
        }
        foreach ($query['nodes'] as $node) {
            if (($node['Relation Name'] ?? null) === 'oauth_refresh_tokens'
                && (($node['Rows Removed by Filter'] ?? 0) > 0 || ($node['Heap Fetches'] ?? 0) > 0)) {
                return true;
            }
        }
    }

    return false;
}

$report = ['scope' => 'fixture-index-comparison', 'stages' => [], 'created_indexes' => [], 'complete' => false];
$reportPath = null;
try {
    $options = getopt('', ['run-existing', 'run-id:', 'execute']);
    Retention::check(PHP_SAPI === 'cli' && isset($options['run-existing']) && ($options['run-id'] ?? null) === 'a701b92e031f', 'Only the approved retained fixture run is accepted.');
    Retention::check(! is_file(Bootstrap::root().'/bootstrap/cache/config.php'), 'Cached configuration refused.');
    $local = Dotenv::parse(file_get_contents(Bootstrap::root().'/.env'));
    Retention::check(($local['APP_ENV'] ?? null) === 'local' && ($local['DB_CONNECTION'] ?? null) === 'pgsql'
        && ($local['DB_HOST'] ?? null) === '127.0.0.1' && empty($local['DB_URL']) && empty($local['DB_SOCKET']), 'Unsafe local connection selection.');
    $keys = RSA::createKey(2048);
    $configuration = ['run_id' => $options['run-id'], 'host' => '127.0.0.1', 'port' => (int) ($local['DB_PORT'] ?? 5432),
        'username' => $local['DB_USERNAME'] ?? '', 'password' => $local['DB_PASSWORD'] ?? '',
        'app_key' => 'base64:'.base64_encode(Encrypter::generateKey('AES-256-CBC')),
        'private_key' => (string) $keys, 'public_key' => (string) $keys->getPublicKey(),
        'test_now' => gmdate('Y-m-d H:i:s'), 'retention_scope' => 'index-'.bin2hex(random_bytes(4))];
    unset($local, $keys);
    Bootstrap::boot($configuration);
    Retention::configure($configuration);
    Retention::check((int) DB::selectOne('SHOW server_version_num')->server_version_num >= 180000, 'PostgreSQL 18 required.');
    $reportPath = Bootstrap::root().'/storage/app/pgsql-retention-index-'.$configuration['run_id'].'-'.gmdate('YmdHis').'-'.bin2hex(random_bytes(4)).'.json';
    $report['server_version'] = DB::selectOne('SHOW server_version')->server_version;
    $report['source_sha256'] = hash('sha256', file_get_contents(__FILE__).file_get_contents(dirname(__DIR__).'/Support/Concurrency/Retention.php'));
    $report['run_id'] = $configuration['run_id'];
    foreach (['enable_seqscan', 'enable_indexscan', 'enable_indexonlyscan', 'enable_bitmapscan'] as $setting) {
        $value = DB::selectOne('SELECT current_setting(?) AS value', [$setting])->value;
        Retention::check($value === 'on', 'Nondefault scan enablement refused.');
        $report['planner_settings'][$setting] = $value;
    }
    $report['inventory_before'] = retentionIndexInventory();
    $report['counts_before'] = Retention::counts();
    $drives = PHP_OS_FAMILY === 'Windows' ? ['C:\\', 'D:\\'] : [Bootstrap::root()];
    foreach ($drives as $drive) {
        $available = disk_free_space($drive);
        Retention::check(is_float($available) && $available >= 536870912, 'Insufficient verified local disk space for fixture indexes.');
        $report['available_disk_bytes'][] = (int) $available;
    }
    DB::statement("SET lock_timeout = '5s'");
    DB::statement("SET statement_timeout = '30s'");
    foreach (['oauth_access_tokens', 'oauth_refresh_tokens'] as $table) {
        DB::statement('ANALYZE "'.$table.'"');
    }
    $before = Retention::snapshot();
    $cutoff = CarbonImmutable::now()->subDays(30);
    $samples = retentionIndexSamples($cutoff);
    $queries = retentionIndexQueries($samples, $cutoff);
    DB::statement("SET statement_timeout = '5s'");
    $report['stages']['baseline'] = retentionIndexMeasure($queries, $samples, $cutoff);
    file_put_contents($reportPath, json_encode($report, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), LOCK_EX);
    echo json_encode(['stage' => 'baseline', 'queries' => count($queries)], JSON_THROW_ON_ERROR).PHP_EOL;
    if (isset($options['execute'])) {
        foreach (['retention_probe_access_family_a701b92e031f', 'retention_probe_refresh_expiry_a701b92e031f'] as $name) {
            Retention::check(DB::selectOne('SELECT to_regclass(?) AS existing', ['public.'.$name])->existing === null, 'Candidate index exists; refusing to overwrite or recreate.');
        }
        $candidates = ['access' => ['name' => 'retention_probe_access_family_a701b92e031f',
            'ddl' => 'CREATE INDEX retention_probe_access_family_a701b92e031f ON public.oauth_access_tokens (auth_code_id, client_id, user_id, expires_at) INCLUDE (id)'],
            'refresh' => ['name' => 'retention_probe_refresh_expiry_a701b92e031f',
                'ddl' => 'CREATE INDEX retention_probe_refresh_expiry_a701b92e031f ON public.oauth_refresh_tokens (access_token_id, expires_at)']];
        foreach ($candidates as $kind => $candidate) {
            if ($kind === 'refresh' && ! retentionIndexRefreshWorkRemains($report['stages']['access'])) {
                $report['refresh_skipped'] = 'No avoidable refresh filtering/heap fetch found after access candidate.';
                break;
            }
            Bootstrap::guard(DB::connection()->getPdo(), $configuration['run_id']);
            DB::statement("SET statement_timeout = '30s'");
            $started = microtime(true);
            DB::statement($candidate['ddl']);
            $bytes = (int) DB::selectOne('SELECT pg_relation_size(?::regclass) AS bytes', ['public.'.$candidate['name']])->bytes;
            $report['created_indexes'][] = ['name' => $candidate['name'], 'bytes' => $bytes, 'build_ms' => round((microtime(true) - $started) * 1000, 3)];
            Retention::check($bytes < 134217728, 'Fixture candidate exceeds 128 MiB review budget; retained for review.');
            foreach (['oauth_access_tokens', 'oauth_refresh_tokens'] as $table) {
                DB::statement('ANALYZE "'.$table.'"');
            }
            DB::statement("SET statement_timeout = '5s'");
            $report['stages'][$kind] = retentionIndexMeasure($queries, $samples, $cutoff);
            $report['checks'][$kind.'_unchanged_rows'] = Retention::snapshot() === $before;
            $report['checks'][$kind.'_unchanged_preview'] = $report['stages'][$kind]['preview_reports'] === $report['stages']['baseline']['preview_reports'];
            $report['checks'][$kind.'_unchanged_results'] = array_column($report['stages'][$kind]['queries'], 'result_sha256') === array_column($report['stages']['baseline']['queries'], 'result_sha256');
            file_put_contents($reportPath, json_encode($report, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), LOCK_EX);
            echo json_encode(['stage' => $kind, 'index_bytes' => $bytes], JSON_THROW_ON_ERROR).PHP_EOL;
        }
    }
    $report['checks']['unchanged_rows'] = Retention::snapshot() === $before;
    $report['checks']['unchanged_counts'] = Retention::counts() === $report['counts_before'];
    $report['inventory_after'] = retentionIndexInventory();
    $report['complete'] = ! in_array(false, $report['checks'], true);
    $report['mode'] = isset($options['execute']) ? 'execute' : 'inspect';
    file_put_contents($reportPath, json_encode($report, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), LOCK_EX);
    Retention::check($report['complete'], 'Index experiment changed fixture data or preview results.');
    echo json_encode(['complete' => true, 'mode' => $report['mode'], 'report' => $reportPath, 'indexes_created' => count($report['created_indexes'])], JSON_THROW_ON_ERROR).PHP_EOL;
    exit(0);
} catch (Throwable $exception) {
    $failure = ['classification' => 'index_experiment_failed', 'exception_class' => get_class($exception),
        'source_file' => basename($exception->getFile()), 'source_line' => $exception->getLine()];
    if (get_class($exception) === RuntimeException::class && in_array(basename($exception->getFile()), ['PostgresRetentionIndexTest.php', 'Retention.php', 'Bootstrap.php'], true)) {
        $failure['reason'] = $exception->getMessage();
    }
    $report['failure'] = $failure;
    if ($reportPath !== null) {
        file_put_contents($reportPath, json_encode($report, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), LOCK_EX);
    }
    echo json_encode($failure, JSON_THROW_ON_ERROR).PHP_EOL;
    exit(2);
}
