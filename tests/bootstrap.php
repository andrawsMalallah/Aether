<?php

require dirname(__DIR__).'/vendor/autoload.php';

// CI supplies its own environment; local credentials stay in ignored .env.testing.
Dotenv\Dotenv::createImmutable(dirname(__DIR__), '.env.testing')->safeLoad();

if (is_file(dirname(__DIR__).'/bootstrap/cache/config.php')
    || ($_ENV['DB_CONNECTION'] ?? getenv('DB_CONNECTION')) !== 'pgsql'
    || ! in_array($_ENV['DB_HOST'] ?? getenv('DB_HOST'), ['127.0.0.1', 'localhost', '::1'], true)
    || ! preg_match('/^aether_testing(?:_[a-z0-9]+)?$/D', (string) ($_ENV['DB_DATABASE'] ?? getenv('DB_DATABASE')))) {
    throw new RuntimeException('Tests require a dedicated PostgreSQL aether_testing database.');
}
