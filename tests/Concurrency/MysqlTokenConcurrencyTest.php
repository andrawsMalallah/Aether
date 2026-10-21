<?php

// Explicit standalone runner: never discovered by the normal Unit/Feature suites.
use App\Actions\OAuth\CompleteConsent;
use App\Enums\OAuthAppType;
use App\Enums\OAuthClientStatus;
use App\Models\AuditLog;
use App\Models\OAuthClient;
use App\Models\User;
use App\Services\OAuth\ReadToken;
use Dotenv\Dotenv;
use GuzzleHttp\Psr7\Response as PsrResponse;
use GuzzleHttp\Psr7\ServerRequest;
use Illuminate\Encryption\Encrypter;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Laravel\Passport\Bridge\User as BridgeUser;
use Laravel\Passport\Client;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResourceServer;
use phpseclib4\Crypt\RSA;
use Tests\Support\Concurrency\Bootstrap;
use Tests\Support\Concurrency\WorkerProcess;

require dirname(__DIR__, 2).'/vendor/autoload.php';
require dirname(__DIR__).'/Support/Concurrency/Lifecycle.php';
require dirname(__DIR__).'/Support/Concurrency/Rollback.php';
ini_set('display_errors', '0');
ini_set('log_errors', '0');

/** @param array<string, mixed> $configuration */
function provisionConcurrencyDatabase(array $configuration): void
{
    $pdo = Bootstrap::pdo($configuration, false);
    $database = Bootstrap::databaseName($configuration['run_id']);
    $statement = $pdo->prepare('SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME = ?');
    $statement->execute([$database]);
    if ($statement->fetchColumn() !== false) {
        throw new RuntimeException('Refusing to provision an existing database.');
    }
    $pdo->exec('CREATE DATABASE `'.$database.'` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci');
    $pdo->exec('USE `'.$database.'`');
    $pdo->exec('CREATE TABLE concurrency_run (run_id CHAR(12) PRIMARY KEY, owner_hash CHAR(64) NOT NULL, schema_version INT NOT NULL) ENGINE=InnoDB');
    $statement = $pdo->prepare('INSERT INTO concurrency_run (run_id, owner_hash, schema_version) VALUES (?, ?, 1)');
    $statement->execute([$configuration['run_id'], Bootstrap::owner()]);
}

/** @return array<string, mixed> */
function concurrencyCode(User $user, Client $client): array
{
    $verifier = Str::random(64);
    $nonce = Str::random(32);
    $authTime = time();
    $parameters = ['client_id' => $client->id, 'response_type' => 'code', 'redirect_uri' => $client->redirect_uris[0],
        'scope' => 'openid email', 'nonce' => $nonce, 'state' => Str::random(32), 'code_challenge_method' => 'S256',
        'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=')];
    $authorization = app(AuthorizationServer::class)->validateAuthorizationRequest((new ServerRequest('GET', 'https://aether-concurrency.test/oauth/authorize'))->withQueryParams($parameters));
    $authorization->setUser(new BridgeUser((string) $user->id));
    $authorization->authTime = $authTime;
    $response = app(CompleteConsent::class)->handle($authorization, $user, true, new PsrResponse);
    parse_str((string) parse_url($response->getHeaderLine('Location'), PHP_URL_QUERY), $callback);
    if (! is_string($callback['code'] ?? null)) {
        throw new RuntimeException('Fixture code issuance failed.');
    }

    return ['data' => ['grant_type' => 'authorization_code', 'client_id' => $client->id, 'code' => $callback['code'],
        'redirect_uri' => $client->redirect_uris[0], 'code_verifier' => $verifier,
        ...($client->plainSecret ? ['client_secret' => $client->plainSecret] : [])],
        'identity' => ['user_id' => $user->id, 'client_id' => $client->id, 'nonce' => $nonce, 'auth_time' => $authTime]];
}

/** @param array<string, mixed> $data
 * @return array<string, mixed>
 */
function concurrencyIssue(array $data): array
{
    $response = Bootstrap::request(app(), '/oauth/token', $data);
    if ($response->getStatusCode() !== 200) {
        throw new RuntimeException('Fixture token issuance failed.');
    }

    return json_decode($response->getContent(), true, flags: JSON_THROW_ON_ERROR);
}

function concurrencyBearerValid(string $token): bool
{
    try {
        app(ResourceServer::class)->validateAuthenticatedRequest((new ServerRequest('GET', 'https://aether-concurrency.test/oauth/userinfo'))->withHeader('Authorization', 'Bearer '.$token));

        return true;
    } catch (OAuthServerException) {
        return false;
    }
}

function concurrencyClient(bool $confidential): Client
{
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Concurrency fixture', ['https://client.example/callback'], $confidential);
    $client->forceFill(['status' => OAuthClientStatus::Live, 'app_type' => $confidential ? OAuthAppType::Web : OAuthAppType::Spa,
        'allowed_scopes' => ['openid', 'email']])->save();

    return $client;
}

/** @param array<string, mixed> $configuration
 * @return array<string, mixed>
 */
function concurrencyFixture(array $configuration, bool $codeOnly, bool $confidential): array
{
    Bootstrap::guard(DB::connection()->getPdo(), $configuration['run_id']);
    $user = User::create(['name' => 'Concurrency fixture', 'email' => 'concurrency-'.Str::uuid().'@example.test', 'password' => Str::random(48)]);
    $user->forceFill(['email_verified_at' => now()])->save();
    $client = concurrencyClient($confidential);
    $otherUser = User::create(['name' => 'Concurrency sentinel', 'email' => 'concurrency-'.Str::uuid().'@example.test', 'password' => Str::random(48)]);
    $otherUser->forceFill(['email_verified_at' => now()])->save();
    $sentinels = [];
    foreach ([[$user, $client], [$otherUser, $client], [$user, concurrencyClient(false)]] as [$owner, $application]) {
        $sentinels[] = concurrencyIssue(concurrencyCode($owner, $application)['data'])['access_token'];
    }
    $code = concurrencyCode($user, $client);
    $credentials = ['client_id' => $client->id, ...($client->plainSecret ? ['client_secret' => $client->plainSecret] : [])];
    $fixture = ['credentials' => $credentials, 'code' => $code['data'], 'identity' => $code['identity'],
        'user_id' => $user->id, 'client_id' => $client->id, 'sentinels' => $sentinels];
    if ($codeOnly) {
        $fixture['family'] = Passport::authCode()->newQuery()->where('user_id', $user->id)->where('client_id', $client->id)->where('revoked', false)->sole()->id;
    } else {
        $tokens = concurrencyIssue($code['data']);
        $fixture['tokens'] = $tokens;
        $fixture['access_id'] = app(ReadToken::class)->access($tokens['access_token']);
        $fixture['refresh_id'] = app(ReadToken::class)->refresh($tokens['refresh_token'])['refresh_token_id'];
        $fixture['family'] = Passport::token()->newQuery()->findOrFail($fixture['access_id'])->auth_code_id;
    }
    foreach (['unknown-'.Str::uuid(), $sentinels[2]] as $unownedToken) {
        $control = Bootstrap::request(app(), '/oauth/revoke', [...$credentials, 'token' => $unownedToken]);
        if ($control->getStatusCode() !== 200 || $control->getContent() !== '' || ! concurrencyBearerValid($sentinels[2])) {
            throw new RuntimeException('Unknown or foreign token revocation control failed.');
        }
    }
    if ($confidential) {
        $control = Bootstrap::request(app(), '/oauth/revoke', [...$credentials, 'client_secret' => 'invalid-fixture-secret', 'token' => $sentinels[0]]);
        if ($control->getStatusCode() !== 401 || ! concurrencyBearerValid($sentinels[0])) {
            throw new RuntimeException('Confidential authentication control failed.');
        }
    }
    $fixture['audit_before'] = AuditLog::where('user_id', $user->id)->where('client_id', $client->id)->get()->groupBy('event')->map->count()->all();

    return $fixture;
}

/** @param array<string, mixed> $fixture
 * @return array<string, mixed>
 */
function concurrencyAction(array $fixture, string $action, bool $cycle): array
{
    $data = $fixture['credentials'];
    $path = '/oauth/token';
    if ($action === 'code') {
        $data = $fixture['code'];
    } elseif ($action === 'refresh') {
        $data += ['grant_type' => 'refresh_token', 'refresh_token' => $fixture['tokens']['refresh_token'], 'scope' => 'openid'];
    } else {
        $path = '/oauth/revoke';
        $data['token'] = $fixture['tokens'][$action === 'revoke_access' ? 'access_token' : 'refresh_token'];
    }
    $gate = match (true) {
        $action === 'code' => ['table' => 'oauth_clients', 'operation' => 'select', 'identifier' => $fixture['client_id']],
        $cycle && $action === 'refresh', $cycle && $action === 'revoke_refresh' => ['table' => 'oauth_refresh_tokens', 'operation' => 'select', 'identifier' => $fixture['refresh_id']],
        $cycle && $action === 'revoke_access', $action === 'revoke_refresh' => ['table' => 'oauth_access_tokens', 'operation' => 'select', 'identifier' => $fixture['access_id']],
        $action === 'refresh' => ['table' => 'oauth_access_tokens', 'operation' => 'update', 'identifier' => $fixture['access_id']],
        default => ['table' => 'oauth_refresh_tokens', 'operation' => 'update', 'identifier' => $fixture['access_id']],
    };

    return ['path' => $path, 'data' => $data, 'gate' => $gate, 'identity' => $fixture['identity']];
}

/** @return array<string, mixed> */
function concurrencyWait(PDO $pdo, string $database, int $requester, int $blocker): array
{
    try {
        $statement = $pdo->prepare('SELECT COUNT(*) AS wait_count, MIN(l.OBJECT_NAME) AS requested_table FROM performance_schema.data_lock_waits w JOIN performance_schema.threads r ON r.THREAD_ID = w.REQUESTING_THREAD_ID JOIN performance_schema.threads b ON b.THREAD_ID = w.BLOCKING_THREAD_ID JOIN performance_schema.data_locks l ON l.ENGINE_LOCK_ID = w.REQUESTING_ENGINE_LOCK_ID AND l.ENGINE = w.ENGINE WHERE r.PROCESSLIST_ID = ? AND b.PROCESSLIST_ID = ? AND l.OBJECT_SCHEMA = ?');
        $statement->execute([$requester, $blocker, $database]);
        $wait = $statement->fetch(PDO::FETCH_ASSOC);

        return ['available' => true, 'observed' => (int) $wait['wait_count'] > 0, 'requested_table' => $wait['requested_table']];
    } catch (PDOException $exception) {
        return ['available' => false, 'observed' => false, 'sqlstate' => $exception->errorInfo[0] ?? null, 'vendor_code' => (int) ($exception->errorInfo[1] ?? 0)];
    }
}

/** @param array<string, mixed> $configuration
 * @return array<string, mixed>
 */
function concurrencyScenario(array $configuration, string $name, string $firstAction, string $secondAction, bool $cycle, bool $confidential): array
{
    $fixture = concurrencyFixture($configuration, $firstAction === 'code', $confidential);
    $first = $second = null;
    try {
        $first = new WorkerProcess(['configuration' => $configuration, 'worker' => 'first', ...concurrencyAction($fixture, $firstAction, $cycle)]);
        $firstReady = $first->await('ready');
        $first->await('paused');
        $second = new WorkerProcess(['configuration' => $configuration, 'worker' => 'second', ...concurrencyAction($fixture, $secondAction, $cycle)]);
        $secondReady = $second->await('ready');
        $observation = ['available' => true, 'observed' => false];
        $cycleFormed = false;
        $deadline = microtime(true) + 5;
        do {
            if ($cycle && $second->event('paused') !== null) {
                // Preserve the original failing schedule when opposing locks are reachable.
                $cycleFormed = true;
                break;
            }
            $observation = concurrencyWait(DB::connection()->getPdo(), Bootstrap::databaseName($configuration['run_id']), $secondReady['connection'], $firstReady['connection']);
            if ($observation['observed'] || ! $observation['available']) {
                break;
            }
            usleep(10000);
        } while (microtime(true) < $deadline);
        $serializedAtClient = $observation['observed'] && ($observation['requested_table'] ?? null) === 'oauth_clients';
        $first->send(['release' => 'first']);
        if ($cycleFormed) {
            $second->send(['release' => 'second']);
        }
        $firstResult = $first->await('result');
        if (! $cycleFormed) {
            $deadline = microtime(true) + 15;
            while ($second->event('result') === null) {
                if ($second->event('paused') !== null) {
                    $second->send(['release' => 'second']);
                    break;
                }
                if (microtime(true) >= $deadline) {
                    throw new RuntimeException('Second worker did not complete or reach its barrier.');
                }
                usleep(10000);
            }
        }
        $secondResult = $second->await('result');
        $activeAccess = Passport::token()->newQuery()->where('auth_code_id', $fixture['family'])->where('revoked', false)->count();
        $activeRefresh = Passport::refreshToken()->newQuery()->where('revoked', false)->whereIn('access_token_id', Passport::token()->newQuery()->where('auth_code_id', $fixture['family'])->select('id'))->count();
        $sentinelsValid = ! in_array(false, array_map('concurrencyBearerValid', $fixture['sentinels']), true);
        $audits = AuditLog::where('user_id', $fixture['user_id'])->where('client_id', $fixture['client_id'])->get()->groupBy('event')->map->count()->all();
        foreach ($fixture['audit_before'] as $event => $count) {
            $audits[$event] -= $count;
        }
        $audits = array_filter($audits);
        $results = [$firstResult, $secondResult];
        $deadlock = collect($results)->flatMap(fn (array $result): array => $result['database_errors'])->contains(fn (array $error): bool => $error['vendor_code'] === 1213 && $error['sqlstate'] === '40001');
        $identityValid = ! in_array(false, array_column($results, 'identity_valid'), true);
        $statuses = array_column($results, 'status');
        $auditValid = match (true) {
            $firstAction === 'code' => ($audits['token.issued'] ?? 0) === 1 && ($audits['code.replayed'] ?? 0) === 1,
            $firstAction === 'refresh' && $secondAction === 'refresh' => ($audits['token.refreshed'] ?? 0) === 1 && ($audits['refresh.replayed'] ?? 0) === 1,
            default => ($audits['token.revoked'] ?? 0) === ($firstAction === 'refresh' || $secondAction === 'refresh' ? 1 : 2)
                && ($audits['token.refreshed'] ?? 0) === ($firstAction === 'refresh' ? 1 : 0),
        };
        $expected = match (true) {
            $firstAction === 'code', $firstAction === 'refresh' && $secondAction === 'refresh' => $statuses === [200, 400] && $secondResult['oauth_error'] === 'invalid_grant' && $activeAccess === 0 && $activeRefresh === 0,
            $firstAction === 'refresh' => $statuses === [200, 200] && $activeAccess === 1 && $activeRefresh === 1,
            $secondAction === 'refresh' => $statuses === [200, 400] && $activeAccess === 0 && $activeRefresh === 0,
            default => $statuses === [200, 200] && $activeAccess === 0 && $activeRefresh === 0,
        };
        $classification = $deadlock ? 'confirmed_deadlock' : ($expected && $sentinelsValid && $identityValid && $auditValid
            && $observation['observed'] && (! $cycle || $serializedAtClient) ? 'passed' : 'needs_review');

        return ['scenario' => $name, 'confidential' => $confidential, 'cycle' => $cycle, 'classification' => $classification,
            'first_action' => $firstAction, 'second_action' => $secondAction, 'connection_ids' => [$firstReady['connection'], $secondReady['connection']],
            'lock_wait' => $observation, 'cycle_formed' => $cycleFormed, 'serialized_at_client' => $serializedAtClient, 'results' => $results,
            'active_family_access' => $activeAccess, 'active_family_refresh' => $activeRefresh,
            'sentinels_valid' => $sentinelsValid, 'identity_context_valid' => $identityValid, 'audits' => $audits];
    } finally {
        $first?->close();
        $second?->close();
    }
}

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
    if (! extension_loaded('pdo_mysql') || ! function_exists('proc_open') || is_file(Bootstrap::root().'/bootstrap/cache/config.php')) {
        throw new RuntimeException('Required local test capabilities unavailable.');
    }
    // Read only connection selection privately; never boot the app with the local .env.
    $local = Dotenv::parse(file_get_contents(Bootstrap::root().'/.env'));
    if (($local['APP_ENV'] ?? null) !== 'local' || ($local['DB_CONNECTION'] ?? null) !== 'mysql'
        || ($local['DB_HOST'] ?? null) !== '127.0.0.1' || ! empty($local['DB_URL']) || ! empty($local['DB_SOCKET'])) {
        throw new RuntimeException('Local connection safety guard failed.');
    }
    $keys = RSA::createKey(2048);
    $configuration = ['run_id' => $runId, 'host' => '127.0.0.1', 'port' => (int) ($local['DB_PORT'] ?? 3306),
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
    $engines = $pdo->prepare('SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? AND ENGINE <> ?');
    $engines->execute([$database, 'InnoDB']);
    if ((int) $engines->fetchColumn() !== 0) {
        throw new RuntimeException('Non-InnoDB table refused.');
    }
    $report = ['database' => $database, 'run_id' => $runId, 'server_version' => $pdo->query('SELECT VERSION()')->fetchColumn(),
        'isolation' => $pdo->query('SELECT @@transaction_isolation')->fetchColumn(), 'results' => []];
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
    $reportPath = Bootstrap::root().'/storage/app/mysql-concurrency-'.$runId.'-'.gmdate('YmdHis').'.json';
    file_put_contents($reportPath, json_encode($report, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR), LOCK_EX);
    echo json_encode(['database' => $database, 'report' => $reportPath, 'scenarios' => count($report['results']),
        'findings' => count(array_filter($report['results'], fn (array $result): bool => $result['classification'] !== 'passed'))], JSON_THROW_ON_ERROR).PHP_EOL;
    exit(count(array_filter($report['results'], fn (array $result): bool => $result['classification'] !== 'passed')) > 0 ? 1 : 0);
} catch (Throwable $exception) {
    // Never print arbitrary exception text, SQL, connection data or protocol payloads.
    echo json_encode(['classification' => 'harness_setup_or_execution_failure', 'exception_class' => get_class($exception),
        'source_file' => basename($exception->getFile()), 'source_line' => $exception->getLine(),
        'reason' => get_class($exception) === RuntimeException::class && in_array(basename($exception->getFile()), ['MysqlTokenConcurrencyTest.php', 'Bootstrap.php', 'WorkerProcess.php'], true) ? $exception->getMessage() : null], JSON_THROW_ON_ERROR).PHP_EOL;
    exit(2);
}
