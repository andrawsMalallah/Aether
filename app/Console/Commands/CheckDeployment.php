<?php

namespace App\Console\Commands;

use App\Services\OAuth\OidcKeys;
use App\Services\PrivateStorage;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Crypt;
use RuntimeException;
use Throwable;

class CheckDeployment extends Command
{
    protected $signature = 'deployment:check';

    protected $description = 'Validate container configuration without contacting external services';

    public function handle(OidcKeys $keys): int
    {
        try {
            $issuer = config('oidc.issuer');
            $this->requireCondition(app()->environment('production') && config('app.debug') === false);
            $this->requireCondition(is_string($issuer) && filter_var($issuer, FILTER_VALIDATE_URL) !== false
                && parse_url($issuer, PHP_URL_SCHEME) === 'https' && ! parse_url($issuer, PHP_URL_USER)
                && ! parse_url($issuer, PHP_URL_PASS) && ! parse_url($issuer, PHP_URL_QUERY)
                && ! parse_url($issuer, PHP_URL_FRAGMENT) && $issuer === config('app.url'));
            Crypt::getKey();
            $keys->jwks();
            PrivateStorage::name();
            $this->requireCondition(config('database.default') === 'pgsql'
                && config('session.driver') === 'database' && config('session.secure') === true
                && config('cache.default') === 'database' && config('queue.default') === 'database'
                && config('queue.connections.database.queue') === 'default'
                && (int) config('queue.connections.database.retry_after') === 90);
            foreach (['session.connection', 'cache.stores.database.connection', 'cache.stores.database.lock_connection', 'queue.connections.database.connection'] as $setting) {
                $this->requireCondition(in_array(config($setting), [null, '', 'pgsql'], true));
            }
            $this->requireCondition(config('logging.default') === 'stderr'
                && config('mail.default') === 'smtp' && config('mail.mailers.smtp.transport') === 'smtp'
                && filled(config('mail.mailers.smtp.host'))
                && config('filesystems.private_disk') === 'private_s3'
                && filled(config('filesystems.disks.private_s3.bucket'))
                && filled(config('filesystems.disks.private_s3.root'))
                && config('retention.scheduled_enabled') === false);
            foreach (['bootstrap/cache', 'storage/framework/cache/data', 'storage/framework/sessions', 'storage/framework/views'] as $directory) {
                $this->requireCondition(is_writable(base_path($directory)));
            }
            $this->requireCondition(is_writable(sys_get_temp_dir()) && extension_loaded('pcntl')
                && in_array('argon2id', password_algos(), true));
            foreach (['pdo_pgsql', 'mbstring', 'openssl', 'fileinfo', 'dom', 'SimpleXML', 'xml', 'curl', 'sodium', 'gd', 'Zend OPcache'] as $extension) {
                $this->requireCondition(extension_loaded($extension));
            }
            $this->info('Deployment configuration accepted.');

            return self::SUCCESS;
        } catch (Throwable) {
            $this->error('Deployment configuration is invalid.');

            return self::FAILURE;
        }
    }

    private function requireCondition(bool $condition): void
    {
        if (! $condition) {
            throw new RuntimeException;
        }
    }
}
