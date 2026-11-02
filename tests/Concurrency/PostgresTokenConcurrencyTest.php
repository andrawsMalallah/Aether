<?php

// Explicit standalone runner: never discovered by the normal Unit/Feature suites.
use App\Models\OAuthClient;
use App\Models\User;
use Dotenv\Dotenv;
use Illuminate\Encryption\Encrypter;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Laravel\Passport\Passport;
use phpseclib4\Crypt\RSA;
use Tests\Support\Concurrency\Bootstrap;

require dirname(__DIR__, 2).'/vendor/autoload.php';
require dirname(__DIR__).'/Support/Concurrency/Lifecycle.php';
require dirname(__DIR__).'/Support/Concurrency/Rollback.php';
ini_set('display_errors', '0');
ini_set('log_errors', '0');

require dirname(__DIR__).'/Support/Concurrency/TokenFixtures.php';

try {
    $options = getopt('', ['provision-local', 'run-existing', 'run-id:', 'setup-only', 'case:']);
    if (! isset($options['run-id']) || (isset($options['provision-local']) === isset($options['run-existing']))) {
        throw new RuntimeException('Explicit provisioning/resume flag and run identity required.');
    }
    $runId = $options['run-id'];
    Bootstrap::databaseName($runId);
    $allowedCases = [];
    foreach (['code-code', 'refresh-refresh', 'refresh-revoke_access', 'refresh-revoke_refresh', 'revoke_access-revoke_refresh',
        'cycle-refresh-revoke_access', 'cycle-revoke_refresh-revoke_access'] as $case) {
        $allowedCases[] = $case.'-forward';
        $allowedCases[] = $case.'-reverse';
    }
    foreach (['rotate', 'disconnect', 'suspend', 'delete'] as $lifecycle) {
        foreach (['code', 'refresh'] as $issuance) {
            foreach (['issuance-first', 'lifecycle-first'] as $ordering) {
                $allowedCases[] = $issuance.'-'.$lifecycle.'-'.$ordering;
                $allowedCases[] = 'rollback-'.$issuance.'-'.$lifecycle.'-'.$ordering;
            }
        }
    }
    if (PHP_SAPI !== 'cli' || isset($options['case']) && ! in_array($options['case'], $allowedCases, true)) {
        throw new RuntimeException('CLI execution and a recognized case are required.');
    }
    if (! extension_loaded('pdo_pgsql') || ! function_exists('proc_open') || is_file(Bootstrap::root().'/bootstrap/cache/config.php')) {
        throw new RuntimeException('Required local test capabilities unavailable.');
    }
    // Read only connection selection privately; never boot the app with the local .env.
    $local = Dotenv::parse(file_get_contents(Bootstrap::root().'/.env'));
    if (($local['APP_ENV'] ?? null) !== 'local' || ($local['DB_CONNECTION'] ?? null) !== 'pgsql'
        || ($local['DB_HOST'] ?? null) !== '127.0.0.1' || ! empty($local['DB_URL']) || ! empty($local['DB_SOCKET'])) {
        throw new RuntimeException('Local connection safety guard failed.');
    }
    $keys = RSA::createKey(2048);
    $configuration = ['run_id' => $runId, 'host' => '127.0.0.1', 'port' => (int) ($local['DB_PORT'] ?? 5432),
        'username' => $local['DB_USERNAME'] ?? '', 'password' => $local['DB_PASSWORD'] ?? '',
        'app_key' => 'base64:'.base64_encode(Encrypter::generateKey('AES-256-CBC')),
        'private_key' => (string) $keys, 'public_key' => (string) $keys->getPublicKey()];
    unset($local, $keys);
    if (isset($options['provision-local'])) {
        provisionConcurrencyDatabase($configuration);
    }
    $application = Bootstrap::boot($configuration);
    $pdo = DB::connection()->getPdo();
    Bootstrap::guard($pdo, $runId);
    if (isset($options['provision-local'])) {
        Artisan::call('migrate', ['--force' => true]);
    }
    $database = Bootstrap::databaseName($runId);
    $report = ['database' => $database, 'run_id' => $runId, 'server_version' => $pdo->query('SELECT VERSION()')->fetchColumn(),
        'isolation' => $pdo->query('SHOW transaction_isolation')->fetchColumn(), 'results' => []];
    if (! isset($options['setup-only'])) {
        foreach ([['code', 'code'], ['refresh', 'refresh'], ['refresh', 'revoke_access'], ['refresh', 'revoke_refresh'], ['revoke_access', 'revoke_refresh']] as $pair) {
            foreach ([false, true] as $reverse) {
                [$first, $second] = $reverse ? array_reverse($pair) : $pair;
                $name = $pair[0].'-'.$pair[1].($reverse ? '-reverse' : '-forward');
                if (isset($options['case']) && $options['case'] !== $name) {
                    continue;
                }
                echo json_encode(['starting' => $name], JSON_THROW_ON_ERROR).PHP_EOL;
                $report['results'][] = concurrencyScenario($configuration, $name, $first, $second, false, $reverse);
                echo json_encode(end($report['results']), JSON_THROW_ON_ERROR).PHP_EOL;
            }
        }
        foreach ([['refresh', 'revoke_access'], ['revoke_refresh', 'revoke_access']] as $pair) {
            foreach ([false, true] as $reverse) {
                [$first, $second] = $reverse ? array_reverse($pair) : $pair;
                $name = 'cycle-'.$pair[0].'-'.$pair[1].($reverse ? '-reverse' : '-forward');
                if (isset($options['case']) && $options['case'] !== $name) {
                    continue;
                }
                echo json_encode(['starting' => $name], JSON_THROW_ON_ERROR).PHP_EOL;
                $report['results'][] = concurrencyScenario($configuration, $name, $first, $second, true, $reverse);
                echo json_encode(end($report['results']), JSON_THROW_ON_ERROR).PHP_EOL;
            }
        }
        foreach (['rotate', 'disconnect', 'suspend', 'delete'] as $lifecycle) {
            foreach (['code', 'refresh'] as $issuance) {
                foreach ([false, true] as $lifecycleFirst) {
                    $name = $issuance.'-'.$lifecycle.($lifecycleFirst ? '-lifecycle-first' : '-issuance-first');
                    if (isset($options['case']) && $options['case'] !== $name) {
                        continue;
                    }
                    echo json_encode(['starting' => $name], JSON_THROW_ON_ERROR).PHP_EOL;
                    $report['results'][] = lifecycleScenario($configuration, $name, $issuance, $lifecycle, $lifecycleFirst);
                    echo json_encode(end($report['results']), JSON_THROW_ON_ERROR).PHP_EOL;
                }
            }
        }
        foreach (['rotate', 'disconnect', 'suspend', 'delete'] as $lifecycle) {
            foreach (['code', 'refresh'] as $issuance) {
                foreach ([false, true] as $lifecycleFirst) {
                    $name = 'rollback-'.$issuance.'-'.$lifecycle.($lifecycleFirst ? '-lifecycle-first' : '-issuance-first');
                    if (isset($options['case']) && $options['case'] !== $name) {
                        continue;
                    }
                    echo json_encode(['starting' => $name], JSON_THROW_ON_ERROR).PHP_EOL;
                    $report['results'][] = rollbackScenario($configuration, $name, $issuance, $lifecycle, $lifecycleFirst);
                    echo json_encode(end($report['results']), JSON_THROW_ON_ERROR).PHP_EOL;
                }
            }
        }
    }
    $report['fixture_counts'] = ['users' => User::count(), 'clients' => OAuthClient::count(), 'access_tokens' => Passport::token()->newQuery()->count()];
    $reportPath = Bootstrap::root().'/storage/app/pgsql-concurrency-'.$runId.'-'.gmdate('YmdHis').'.json';
    file_put_contents($reportPath, json_encode($report, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), LOCK_EX);
    echo json_encode(['database' => $database, 'report' => $reportPath, 'scenarios' => count($report['results']),
        'findings' => count(array_filter($report['results'], fn (array $result): bool => $result['classification'] !== 'passed'))], JSON_THROW_ON_ERROR).PHP_EOL;
    exit(count(array_filter($report['results'], fn (array $result): bool => $result['classification'] !== 'passed')) > 0 ? 1 : 0);
} catch (Throwable $exception) {
    // Never print arbitrary exception text, SQL, connection data or protocol payloads.
    echo json_encode(['classification' => 'harness_setup_or_execution_failure', 'exception_class' => get_class($exception),
        'source_file' => basename($exception->getFile()), 'source_line' => $exception->getLine(),
        'reason' => get_class($exception) === RuntimeException::class && in_array(basename($exception->getFile()), ['PostgresTokenConcurrencyTest.php', 'Bootstrap.php', 'WorkerProcess.php'], true) ? $exception->getMessage() : null], JSON_THROW_ON_ERROR).PHP_EOL;
    exit(2);
}
