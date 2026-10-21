<?php

// Explicit local-only setup: never reuse, reset, or remove an existing database/role.
require dirname(__DIR__).'/vendor/autoload.php';

$stage = 'local-configuration';

try {
    $root = dirname(__DIR__);
    $local = Dotenv\Dotenv::parse(file_get_contents($root.'/.env'));
    if (($local['APP_ENV'] ?? null) !== 'local' || is_file($root.'/bootstrap/cache/config.php')) {
        throw new RuntimeException('Local uncached configuration is required.');
    }
    $stage = 'administrator-authentication';
    $pdo = new PDO('pgsql:host=127.0.0.1;port=5432;dbname=postgres;connect_timeout=5',
        getenv('AETHER_PG_ADMIN'), getenv('AETHER_PG_ADMIN_PASSWORD'), [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    $stage = 'empty-target-check';
    if ($pdo->query("SELECT count(*) FROM pg_database WHERE datname IN ('aether', 'aether_testing')")->fetchColumn() != 0
        || $pdo->query("SELECT count(*) FROM pg_roles WHERE rolname = 'aether'")->fetchColumn() != 0
        || is_file($root.'/.env.testing')) {
        throw new RuntimeException('Existing target database, role, or testing configuration refused.');
    }
    $stage = 'fresh-database-provisioning';
    $password = bin2hex(random_bytes(32));
    // CREATEDB is local-only for the explicit isolated concurrency runner, never production.
    $pdo->exec('CREATE ROLE aether LOGIN CREATEDB PASSWORD '.$pdo->quote($password));
    foreach (['aether', 'aether_testing'] as $database) {
        $pdo->exec('CREATE DATABASE "'.$database.'" OWNER aether TEMPLATE template0 ENCODING \'UTF8\'');
    }
    $stage = 'local-configuration-save';
    $settings = ['DB_CONNECTION' => 'pgsql', 'DB_HOST' => '127.0.0.1', 'DB_PORT' => '5432',
        'DB_DATABASE' => 'aether', 'DB_USERNAME' => 'aether', 'DB_PASSWORD' => $password,
        'DB_URL' => '', 'DB_SOCKET' => '', 'DB_CHARSET' => 'utf8'];
    // Explicit connection selectors must follow the database switch as well.
    foreach (['SESSION_CONNECTION', 'DB_QUEUE_CONNECTION', 'DB_CACHE_CONNECTION', 'DB_CACHE_LOCK_CONNECTION'] as $name) {
        if (isset($local[$name]) && in_array($local[$name], ['mysql', 'mariadb'], true)) {
            $settings[$name] = 'pgsql';
        }
    }
    $contents = file_get_contents($root.'/.env');
    foreach ($settings as $name => $value) {
        $line = $name.'='.$value;
        $contents = preg_match('/^'.preg_quote($name, '/').'=/m', $contents)
            ? preg_replace('/^'.preg_quote($name, '/').'=.*$/m', $line, $contents)
            : $contents.PHP_EOL.$line.PHP_EOL;
    }
    if (file_put_contents($root.'/.env.testing', 'DB_PASSWORD='.$password.PHP_EOL, LOCK_EX) === false
        || file_put_contents($root.'/.env', $contents, LOCK_EX) === false) {
        throw new RuntimeException('Unable to save local database configuration.');
    }
    echo "Created isolated PostgreSQL aether/aether_testing databases and updated local database settings. MySQL untouched.\n";
} catch (Throwable $exception) {
    // Database exceptions can contain credentials or full SQL; disclose only the class.
    fwrite(STDERR, 'Local PostgreSQL setup failed at '.$stage.' ('.$exception::class."). No existing database was removed.\n");
    exit(1);
}
