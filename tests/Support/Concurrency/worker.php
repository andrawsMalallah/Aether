<?php

use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Tests\Support\Concurrency\Bootstrap;

require dirname(__DIR__, 3).'/vendor/autoload.php';

ini_set('display_errors', '0');
ini_set('log_errors', '0');
set_time_limit(45);

/** @param array<string, mixed> $event */
function concurrencyEvent(array $event): void
{
    fwrite(STDOUT, json_encode($event, JSON_THROW_ON_ERROR)."\n");
    fflush(STDOUT);
}

try {
    $input = json_decode((string) fgets(STDIN), true, flags: JSON_THROW_ON_ERROR);
    $application = Bootstrap::boot($input['configuration']);
    $errors = [];
    $application->make(ExceptionHandler::class)->reportable(function (QueryException $exception) use (&$errors): bool {
        $errors[] = ['sqlstate' => $exception->errorInfo[0] ?? null, 'vendor_code' => (int) ($exception->errorInfo[1] ?? 0)];

        return false;
    });
    $gate = $input['gate'];
    $paused = false;
    $match = function (string $sql, array $bindings) use ($gate): bool {
        return str_contains($sql, '`'.$gate['table'].'`')
            && str_starts_with(strtolower($sql), $gate['operation'])
            && ($gate['operation'] !== 'select' || str_contains($sql, 'for update'))
            && in_array($gate['identifier'], $bindings, true);
    };
    DB::connection()->beforeExecuting(function (string $sql, array $bindings) use ($input): void {
        if (str_contains($sql, 'for update') || str_starts_with(strtolower($sql), 'update ')) {
            foreach (['oauth_clients', 'oauth_access_tokens', 'oauth_refresh_tokens'] as $table) {
                if (str_contains($sql, '`'.$table.'`')) {
                    concurrencyEvent(['type' => 'attempt', 'worker' => $input['worker'], 'table' => $table]);
                    break;
                }
            }
        }
    });
    DB::listen(function (QueryExecuted $query) use ($match, &$paused, $input): void {
        if (! $paused && $match($query->sql, $query->bindings)) {
            $paused = true;
            concurrencyEvent(['type' => 'paused', 'worker' => $input['worker']]);
            $command = json_decode((string) fgets(STDIN), true, flags: JSON_THROW_ON_ERROR);
            if (($command['release'] ?? null) !== $input['worker']) {
                throw new RuntimeException('Invalid worker barrier command.');
            }
        }
    });
    concurrencyEvent(['type' => 'ready', 'worker' => $input['worker'], 'connection' => (int) DB::selectOne('SELECT CONNECTION_ID() AS identifier')->identifier]);
    $response = Bootstrap::request($application, $input['path'], $input['data']);
    $payload = json_decode((string) $response->getContent(), true);
    $identityValid = null;
    if (is_array($payload) && isset($payload['id_token'])) {
        $claims = (new Parser(new JoseEncoder))->parse($payload['id_token'])->claims();
        $expected = $input['identity'];
        $identityValid = $claims->get('sub') === (string) $expected['user_id']
            && $claims->get('aud') === [$expected['client_id']]
            && $claims->get('iss') === 'https://aether-concurrency.test'
            && $claims->get('nonce') === $expected['nonce'] && $claims->get('auth_time') === $expected['auth_time']
            && (($input['data']['grant_type'] ?? null) !== 'refresh_token' || ! $claims->has('email'));
    }
    concurrencyEvent(['type' => 'result', 'worker' => $input['worker'], 'status' => $response->getStatusCode(),
        'oauth_error' => is_array($payload) ? ($payload['error'] ?? null) : null,
        'identity_valid' => $identityValid, 'database_errors' => $errors]);
} catch (Throwable $exception) {
    concurrencyEvent(['type' => 'worker_failure', 'exception_class' => get_class($exception),
        'source_file' => basename($exception->getFile()), 'source_line' => $exception->getLine()]);
    exit(2);
}
