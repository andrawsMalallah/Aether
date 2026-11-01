<?php

// No application bootstrap or diagnostic output. The parent bounds total time,
// including native DNS resolution, and never puts credentials in arguments.
try {
    $configuration = json_decode(stream_get_contents(STDIN), true, flags: JSON_THROW_ON_ERROR);
    $parameters = [];
    foreach (['host', 'port', 'database' => 'dbname', 'sslmode'] as $key => $name) {
        $source = is_int($key) ? $name : $key;
        $value = (string) ($configuration[$source] ?? '');
        if ($value === '' || str_contains($value, ';') || str_contains($value, "\0")) {
            exit(1);
        }
        $parameters[] = $name."='".str_replace(['\\', "'"], ['\\\\', "\\'"], $value)."'";
    }
    $connection = new PDO('pgsql:'.implode(';', $parameters).';connect_timeout=2;options=\'--statement_timeout=1000\'',
        $configuration['username'], $configuration['password'], [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
    exit((int) $connection->query('SELECT 1')->fetchColumn() === 1 ? 0 : 1);
} catch (Throwable) {
    exit(1);
}
