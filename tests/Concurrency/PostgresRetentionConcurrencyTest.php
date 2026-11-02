<?php

// Opt-in only: deliberately outside normal Pest Unit/Feature discovery.
use Dotenv\Dotenv;
use Illuminate\Encryption\Encrypter;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use phpseclib4\Crypt\RSA;
use Symfony\Component\Process\Process;
use Tests\Support\Concurrency\Bootstrap;
use Tests\Support\Concurrency\Retention;

require dirname(__DIR__, 2).'/vendor/autoload.php';
require dirname(__DIR__).'/Support/Concurrency/TokenFixtures.php';
require dirname(__DIR__).'/Support/Concurrency/Lifecycle.php';
require dirname(__DIR__).'/Support/Concurrency/Rollback.php';
ini_set('display_errors', '0');
ini_set('log_errors', '0');

$report = ['scope' => 'setup', 'results' => [], 'complete' => false];
$reportPath = null;
try {
    $options = getopt('', ['provision-local', 'run-existing', 'run-id:', 'setup-only', 'case:']);
    Retention::check(PHP_SAPI === 'cli' && isset($options['run-id'])
        && isset($options['provision-local']) !== isset($options['run-existing']), 'Explicit provision/reuse mode and run identity required.');
    $runId = $options['run-id'];
    Bootstrap::databaseName($runId);
    Retention::check(extension_loaded('pdo_pgsql') && function_exists('proc_open')
        && ! is_file(Bootstrap::root().'/bootstrap/cache/config.php'), 'Local test capabilities unavailable.');
    $manifest = [];
    foreach (range(1, 12) as $number) {
        foreach (['prune-first', 'operation-first'] as $order) {
            $manifest[] = sprintf('R%02d-%s', $number, $order);
        }
    }
    foreach (range(1, 10) as $number) {
        $manifest[] = sprintf('C%02d', $number);
    }
    Retention::check(! isset($options['case']) || in_array($options['case'], [...$manifest, 'plans'], true), 'Unknown retention case.');
    $local = Dotenv::parse(file_get_contents(Bootstrap::root().'/.env'));
    Retention::check(($local['APP_ENV'] ?? null) === 'local' && ($local['DB_CONNECTION'] ?? null) === 'pgsql'
        && ($local['DB_HOST'] ?? null) === '127.0.0.1' && empty($local['DB_URL']) && empty($local['DB_SOCKET']), 'Unsafe local connection selection.');
    $keys = RSA::createKey(2048);
    $configuration = ['run_id' => $runId, 'host' => '127.0.0.1', 'port' => (int) ($local['DB_PORT'] ?? 5432),
        'username' => $local['DB_USERNAME'] ?? '', 'password' => $local['DB_PASSWORD'] ?? '',
        'app_key' => 'base64:'.base64_encode(Encrypter::generateKey('AES-256-CBC')),
        'private_key' => (string) $keys, 'public_key' => (string) $keys->getPublicKey(),
        'test_now' => gmdate('Y-m-d H:i:s'), 'retention_scope' => 'setup'];
    unset($local, $keys);
    if (isset($options['provision-local'])) {
        provisionConcurrencyDatabase($configuration);
    }
    Bootstrap::boot($configuration);
    if (isset($options['provision-local'])) {
        Artisan::call('migrate', ['--force' => true]);
    }
    Retention::configure($configuration);
    Retention::check((int) DB::selectOne('SHOW server_version_num')->server_version_num >= 180000
        && DB::selectOne('SHOW transaction_isolation')->transaction_isolation === 'read committed', 'PostgreSQL 18 READ COMMITTED required.');
    $reportPath = Bootstrap::root().'/storage/app/pgsql-retention-'.$runId.'-'.gmdate('YmdHis').'-'.bin2hex(random_bytes(4)).'.json';
    $report = ['scope' => isset($options['setup-only']) ? 'setup' : (isset($options['case']) ? 'partial' : 'full'),
        'database' => Bootstrap::databaseName($runId), 'run_id' => $runId,
        'server_version' => DB::selectOne('SHOW server_version')->server_version, 'isolation' => 'read committed',
        'source_diff_sha256' => hash('sha256', file_get_contents(__FILE__).file_get_contents(dirname(__DIR__).'/Support/Concurrency/Retention.php').file_get_contents(dirname(__DIR__).'/Support/Concurrency/worker.php')),
        'manifest' => $manifest, 'results' => [], 'complete' => false];
    if (! isset($options['setup-only'])) {
        if (! isset($options['case'])) {
            echo json_encode(['starting' => 'original-46-schedule-matrix'], JSON_THROW_ON_ERROR).PHP_EOL;
            $baseline = new Process([PHP_BINARY, '-d', 'display_errors=0', '-d', 'log_errors=0', __DIR__.'/PostgresTokenConcurrencyTest.php', '--run-existing', '--run-id='.$runId]);
            $baseline->setTimeout(600);
            $baseline->run();
            $lines = array_filter(explode("\n", trim($baseline->getOutput())));
            $summary = json_decode((string) end($lines), true);
            $report['baseline'] = ['exit_code' => $baseline->getExitCode(), 'scenarios' => $summary['scenarios'] ?? 0, 'findings' => $summary['findings'] ?? null, 'report' => $summary['report'] ?? null];
            Retention::check($baseline->isSuccessful() && $report['baseline']['scenarios'] === 46 && $report['baseline']['findings'] === 0, 'Original shared-harness matrix failed.');
            Retention::counts();
            echo json_encode(['baseline' => $report['baseline']], JSON_THROW_ON_ERROR).PHP_EOL;
        }
        // Protocol fixtures must not inherit the baseline's several-minute setup age.
        $configuration['test_now'] = gmdate('Y-m-d H:i:s');
        foreach ($manifest as $scenario) {
            if (isset($options['case']) && $options['case'] !== $scenario) {
                continue;
            }
            echo json_encode(['starting' => $scenario], JSON_THROW_ON_ERROR).PHP_EOL;
            $result = str_starts_with($scenario, 'R') ? Retention::race($configuration, substr($scenario, 0, 3), str_ends_with($scenario, '-prune-first')) : Retention::control($configuration, $scenario);
            $report['results'][] = $result;
            file_put_contents($reportPath, json_encode($report, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), LOCK_EX);
            echo json_encode($result, JSON_THROW_ON_ERROR).PHP_EOL;
            Retention::check($result['classification'] === 'passed', 'Retention assertion failed; inspect safe report.');
        }
        if (! isset($options['case']) || $options['case'] === 'plans') {
            echo json_encode(['starting' => 'query-plans'], JSON_THROW_ON_ERROR).PHP_EOL;
            $report['plans'] = Retention::plans($configuration);
        }
        $report['complete'] = ! isset($options['case']) && count($report['results']) === 34 && ($report['plans']['classification'] ?? null) === 'passed';
    }
    $report['fixture_counts'] = Retention::counts();
    $report['lock_waits'] = count(array_filter($report['results'], fn (array $result): bool => $result['lock_wait']['observed'] ?? false));
    if ($report['scope'] === 'full') {
        Retention::check($report['complete'] && $report['lock_waits'] === 22, 'Incomplete retention manifest or wait evidence.');
    }
    file_put_contents($reportPath, json_encode($report, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), LOCK_EX);
    echo json_encode(['scope' => $report['scope'], 'complete' => $report['complete'], 'report' => $reportPath,
        'scenarios' => count($report['results']), 'observed_waits' => $report['lock_waits']], JSON_THROW_ON_ERROR).PHP_EOL;
    exit(0);
} catch (Throwable $exception) {
    $failure = ['classification' => 'harness_setup_or_execution_failure', 'exception_class' => get_class($exception),
        'source_file' => basename($exception->getFile()), 'source_line' => $exception->getLine()];
    // PDOException also extends RuntimeException; never expose its message/DSN.
    if (get_class($exception) === RuntimeException::class && in_array(basename($exception->getFile()), ['PostgresRetentionConcurrencyTest.php', 'Retention.php', 'Bootstrap.php', 'WorkerProcess.php', 'TokenFixtures.php'], true)) {
        $failure['reason'] = $exception->getMessage();
    }
    $report['failure'] = $failure;
    if ($reportPath !== null) {
        file_put_contents($reportPath, json_encode($report, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), LOCK_EX);
    }
    echo json_encode($failure, JSON_THROW_ON_ERROR).PHP_EOL;
    exit(isset($failure['reason']) && str_contains($failure['reason'], 'assertion failed') ? 1 : 2);
}
