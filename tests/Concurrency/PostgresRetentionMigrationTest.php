<?php

// Opt-in baseline verification: provision only a fresh, owned loopback fixture.
use Dotenv\Dotenv;
use Illuminate\Encryption\Encrypter;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use phpseclib4\Crypt\RSA;
use Tests\Support\Concurrency\Bootstrap;
use Tests\Support\Concurrency\Retention;
use Tests\Support\Concurrency\SchemaBaseline;

require dirname(__DIR__, 2).'/vendor/autoload.php';
require dirname(__DIR__).'/Support/Concurrency/TokenFixtures.php';
ini_set('display_errors', '0');
ini_set('log_errors', '0');

$report = ['complete' => false, 'checks' => []];
$reportPath = null;
try {
    $options = getopt('', ['provision-local', 'run-id:']);
    Retention::check(PHP_SAPI === 'cli' && isset($options['provision-local'], $options['run-id']), 'Explicit fresh provisioning and run identity required.');
    $runId = $options['run-id'];
    Bootstrap::databaseName($runId);
    Retention::check(extension_loaded('pdo_pgsql') && ! is_file(Bootstrap::root().'/bootstrap/cache/config.php'), 'Local test capabilities unavailable.');
    $baselinePath = Bootstrap::root().'/storage/app/migration-consolidation-original-baseline-20261102.json';
    Retention::check(is_file($baselinePath), 'Captured pre-consolidation schema required.');
    $original = json_decode(file_get_contents($baselinePath), true, flags: JSON_THROW_ON_ERROR);
    Retention::check(count($original['schema']['tables'] ?? []) === 16 && count($original['migration_history'] ?? []) === 18, 'Unexpected original baseline.');
    $local = Dotenv::parse(file_get_contents(Bootstrap::root().'/.env'));
    Retention::check(($local['APP_ENV'] ?? null) === 'local' && ($local['DB_CONNECTION'] ?? null) === 'pgsql'
        && ($local['DB_HOST'] ?? null) === '127.0.0.1' && empty($local['DB_URL']) && empty($local['DB_SOCKET']), 'Unsafe local connection selection.');
    $keys = RSA::createKey(2048);
    $configuration = ['run_id' => $runId, 'host' => '127.0.0.1', 'port' => (int) ($local['DB_PORT'] ?? 5432),
        'username' => $local['DB_USERNAME'] ?? '', 'password' => $local['DB_PASSWORD'] ?? '',
        'app_key' => 'base64:'.base64_encode(Encrypter::generateKey('AES-256-CBC')),
        'private_key' => (string) $keys, 'public_key' => (string) $keys->getPublicKey()];
    unset($local, $keys);
    provisionConcurrencyDatabase($configuration);
    Bootstrap::boot($configuration);
    $connection = DB::connection()->getPdo();
    Bootstrap::guard($connection, $runId);
    Retention::check((int) DB::selectOne('SHOW server_version_num')->server_version_num >= 180000, 'PostgreSQL 18 required.');
    $reportPath = Bootstrap::root().'/storage/app/migration-consolidation-'.$runId.'-'.gmdate('YmdHis').'.json';
    $report += ['run_id' => $runId, 'database' => Bootstrap::databaseName($runId),
        'original_schema_sha256' => hash_file('sha256', $baselinePath), 'server_version' => DB::selectOne('SHOW server_version')->server_version];
    $migrationNames = array_map(fn (string $path): string => basename($path, '.php'), glob(Bootstrap::root().'/database/migrations/*.php'));
    Retention::check(count($migrationNames) === 11, 'Expected eleven consolidated migrations.');
    Retention::check(Artisan::call('migrate', ['--force' => true]) === 0, 'Fresh baseline migration failed.');
    $fresh = SchemaBaseline::snapshot($connection);
    foreach ($original['schema'] as $category => $expected) {
        $report['checks']['fresh_'.$category] = $fresh[$category] === $expected;
        if (! $report['checks']['fresh_'.$category]) {
            $report['schema_difference'][$category] = ['expected' => $expected, 'actual' => $fresh[$category]];
        }
    }
    Retention::check(! in_array(false, $report['checks'], true), 'Fresh schema differs from original.');
    $history = DB::table('migrations')->orderBy('migration')->pluck('migration')->all();
    $report['checks']['eleven_migration_records'] = $history === $migrationNames;
    // Rollback is permitted only while every application table in this new fixture is empty.
    foreach ($fresh['tables'] as $table) {
        Retention::check(DB::table($table['table_name'])->count() === 0, 'Refusing baseline rollback with application rows.');
    }
    Bootstrap::guard($connection, $runId);
    Retention::check(Artisan::call('migrate:rollback', ['--force' => true]) === 0, 'Empty baseline rollback failed.');
    $rolledBack = SchemaBaseline::snapshot($connection);
    $report['checks']['empty_rollback'] = ! array_filter($rolledBack) && DB::table('migrations')->count() === 0;
    Retention::check($report['checks']['empty_rollback'], 'Baseline rollback left schema objects.');
    Bootstrap::guard($connection, $runId);
    Retention::check(Artisan::call('migrate', ['--force' => true]) === 0, 'Baseline reapply failed.');
    $report['checks']['reapply_matches_original'] = SchemaBaseline::snapshot($connection) === $original['schema'];
    $report['checks']['retention_stays_disabled'] = config('retention.scheduled_enabled') === false;
    $report['checks']['no_open_transaction'] = DB::transactionLevel() === 0;
    $report['complete'] = ! in_array(false, $report['checks'], true) && count($report['checks']) === 10;
    Retention::check($report['complete'], 'Consolidated baseline verification failed.');
    file_put_contents($reportPath, json_encode($report, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), LOCK_EX);
    echo json_encode(['complete' => true, 'checks' => count($report['checks']), 'run_id' => $runId, 'report' => $reportPath], JSON_THROW_ON_ERROR).PHP_EOL;
    exit(0);
} catch (Throwable $exception) {
    $report['failure'] = ['exception_class' => get_class($exception), 'source_file' => basename($exception->getFile()), 'source_line' => $exception->getLine()];
    if (get_class($exception) === RuntimeException::class && in_array(basename($exception->getFile()), ['PostgresRetentionMigrationTest.php', 'Retention.php', 'Bootstrap.php', 'TokenFixtures.php'], true)) {
        $report['failure']['reason'] = $exception->getMessage();
    }
    if ($reportPath !== null) {
        file_put_contents($reportPath, json_encode($report, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), LOCK_EX);
    }
    echo json_encode($report['failure'], JSON_THROW_ON_ERROR).PHP_EOL;
    exit(1);
}
