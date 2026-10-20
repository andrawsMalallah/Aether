<?php

namespace Tests\Support\Concurrency;

use Illuminate\Contracts\Console\Kernel;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Queue;
use PDO;
use RuntimeException;
use Symfony\Component\HttpFoundation\Response;

final class Bootstrap
{
    public static function root(): string
    {
        return dirname(__DIR__, 3);
    }

    public static function databaseName(string $runId): string
    {
        if (! preg_match('/^[a-f0-9]{12}$/D', $runId)) {
            throw new RuntimeException('Invalid concurrency run identity.');
        }

        return 'aether_concurrency_20261020_'.$runId;
    }

    public static function owner(): string
    {
        return hash('sha256', strtolower((string) realpath(self::root())));
    }

    /** @param array<string, mixed> $configuration */
    public static function pdo(array $configuration, bool $selectDatabase = true): PDO
    {
        $database = self::databaseName($configuration['run_id']);
        if ($configuration['host'] !== '127.0.0.1' || ! is_int($configuration['port'])
            || $configuration['port'] < 1 || $configuration['port'] > 65535) {
            throw new RuntimeException('Only explicit loopback MySQL is allowed.');
        }
        $pdo = new PDO('mysql:host=127.0.0.1;port='.$configuration['port'].($selectDatabase ? ';dbname='.$database : '').';charset=utf8mb4',
            $configuration['username'], $configuration['password'], [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 5]);
        if ($selectDatabase) {
            self::guard($pdo, $configuration['run_id']);
        }

        return $pdo;
    }

    public static function guard(PDO $pdo, string $runId): void
    {
        if ($pdo->query('SELECT DATABASE()')->fetchColumn() !== self::databaseName($runId)) {
            throw new RuntimeException('Database identity mismatch.');
        }
        $statement = $pdo->prepare('SELECT owner_hash, schema_version FROM concurrency_run WHERE run_id = ?');
        $statement->execute([$runId]);
        $marker = $statement->fetch(PDO::FETCH_ASSOC);
        if (! $marker || ! hash_equals(self::owner(), $marker['owner_hash']) || (int) $marker['schema_version'] !== 1) {
            throw new RuntimeException('Run ownership marker mismatch.');
        }
    }

    /** @param array<string, mixed> $configuration */
    public static function boot(array $configuration): Application
    {
        $database = self::databaseName($configuration['run_id']);
        if (is_file(self::root().'/bootstrap/cache/config.php') || $configuration['host'] !== '127.0.0.1') {
            throw new RuntimeException('Cached configuration or unsafe host refused.');
        }
        $overrides = [
            'APP_ENV' => 'testing', 'APP_DEBUG' => 'false', 'APP_URL' => 'https://aether-concurrency.test',
            'APP_KEY' => $configuration['app_key'], 'DB_CONNECTION' => 'mysql', 'DB_HOST' => '127.0.0.1',
            'DB_PORT' => (string) $configuration['port'], 'DB_DATABASE' => $database,
            'DB_USERNAME' => $configuration['username'], 'DB_PASSWORD' => $configuration['password'],
            'DB_URL' => '', 'DB_SOCKET' => '', 'SESSION_DRIVER' => 'database', 'SESSION_CONNECTION' => 'mysql',
            'CACHE_STORE' => 'array', 'QUEUE_CONNECTION' => 'sync', 'MAIL_MAILER' => 'array',
            'HASH_DRIVER' => 'argon2id', 'ARGON_MEMORY' => '1024', 'ARGON_TIME' => '1',
            'PASSPORT_PRIVATE_KEY' => $configuration['private_key'], 'PASSPORT_PUBLIC_KEY' => $configuration['public_key'],
        ];
        foreach ($overrides as $name => $value) {
            putenv($name.'='.$value);
            $_ENV[$name] = $_SERVER[$name] = $value;
        }
        $application = require self::root().'/bootstrap/app.php';
        $application->loadEnvironmentFrom('.env.example');
        $application->make(Kernel::class)->bootstrap();
        if (! $application->environment('testing') || config('database.default') !== 'mysql'
            || config('database.connections.mysql.database') !== $database
            || config('database.connections.mysql.host') !== '127.0.0.1') {
            throw new RuntimeException('Effective test configuration mismatch.');
        }
        self::guard(DB::connection()->getPdo(), $configuration['run_id']);
        DB::statement('SET SESSION innodb_lock_wait_timeout = 8');
        Http::preventStrayRequests();
        Notification::fake();
        Queue::fake();

        return $application;
    }

    /** @param array<string, mixed> $data */
    public static function request(Application $application, string $path, array $data): Response
    {
        $request = Request::create('https://aether-concurrency.test'.$path, 'POST', $data, [], [],
            ['HTTP_ACCEPT' => 'application/json', 'REMOTE_ADDR' => '127.0.0.1']);
        $kernel = $application->make(HttpKernel::class);
        $response = $kernel->handle($request);
        $kernel->terminate($request, $response);

        return $response;
    }
}
