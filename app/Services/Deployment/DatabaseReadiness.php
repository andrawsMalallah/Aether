<?php

namespace App\Services\Deployment;

use Illuminate\Support\Facades\DB;
use Symfony\Component\Process\Process;
use Throwable;

class DatabaseReadiness
{
    public function ready(): bool
    {
        try {
            // Use Laravel's resolved URL configuration, but a separate bounded connection.
            $configuration = DB::connection()->getConfig();
            if (($configuration['driver'] ?? null) !== 'pgsql') {
                return false;
            }
            // Reject libpq host lists so connect_timeout cannot multiply across targets.
            if (! preg_match('/^[a-zA-Z0-9_.:-]+$/D', (string) ($configuration['host'] ?? ''))
                || ! preg_match('/^[0-9]{1,5}$/D', (string) ($configuration['port'] ?? ''))) {
                return false;
            }
            // libpq DNS resolution can outlive connect_timeout. Bound the entire
            // probe in a child process, passing credentials only through stdin.
            // Under mod_php PHP_BINARY identifies Apache, not the CLI interpreter.
            $phpExecutable = PHP_SAPI === 'cli' ? PHP_BINARY
                : (PHP_OS_FAMILY === 'Windows' ? dirname(PHP_BINARY).DIRECTORY_SEPARATOR.'php.exe' : PHP_BINDIR.'/php');
            $probe = new Process([$phpExecutable, base_path('docker/database-probe.php')]);
            $probe->setInput(json_encode(array_intersect_key($configuration,
                array_flip(['host', 'port', 'database', 'username', 'password', 'sslmode'])), JSON_THROW_ON_ERROR));
            $probe->setTimeout(3);
            $probe->disableOutput();

            return $probe->run() === 0;
        } catch (Throwable) {
            // Health failures are deliberately fixed and never log DSNs or exception messages.
            return false;
        }
    }
}
