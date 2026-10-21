<?php

use App\Actions\Account\DisconnectApp;
use App\Actions\Account\RequestAccountDeletion;
use App\Actions\Admin\SuspendApplication;
use App\Actions\Developer\RegenerateApplicationSecret;
use App\Enums\OAuthAuditEvent;
use App\Enums\OAuthClientStatus;
use App\Models\AuditLog;
use App\Models\Consent;
use App\Models\OAuthClient;
use App\Models\User;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Queue;
use Laravel\Passport\Passport;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Symfony\Component\HttpFoundation\Response;
use Tests\Support\Concurrency\Bootstrap;

require dirname(__DIR__, 3).'/vendor/autoload.php';

ini_set('display_errors', '0');
ini_set('log_errors', '0');
set_time_limit(45);

final class InjectedLifecycleFailure extends RuntimeException {}

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
    $injection = ['count' => 0, 'in_transaction' => false, 'mutations_observed' => false];
    $injectedFailure = false;
    $application->make(ExceptionHandler::class)->reportable(function (QueryException $exception) use (&$errors): bool {
        $errors[] = ['sqlstate' => $exception->errorInfo[0] ?? null, 'vendor_code' => (int) ($exception->errorInfo[1] ?? 0)];

        return false;
    });
    $gate = $input['gate'];
    $paused = false;
    $match = function (string $sql, array $bindings) use ($gate): bool {
        return str_contains($sql, '"'.$gate['table'].'"')
            && str_starts_with(strtolower($sql), $gate['operation'])
            && ($gate['operation'] !== 'select' || str_contains($sql, 'for update'))
            && in_array($gate['identifier'], $bindings, true);
    };
    DB::connection()->beforeExecuting(function (string $sql, array $bindings) use ($input): void {
        if (str_contains($sql, 'for update') || str_starts_with(strtolower($sql), 'update ')) {
            foreach (['users', 'consents', 'oauth_clients', 'oauth_access_tokens', 'oauth_refresh_tokens'] as $table) {
                if (str_contains($sql, '"'.$table.'"')) {
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
    concurrencyEvent(['type' => 'ready', 'worker' => $input['worker'], 'connection' => (int) DB::selectOne('SELECT pg_backend_pid() AS identifier')->identifier]);
    if (isset($input['lifecycle'])) {
        // Test-only action invocation retains the real action policies and transactions.
        // Browser middleware is covered by the normal feature suite, not this worker.
        auth()->setUser(User::findOrFail($input['actor_id']));
        if (isset($input['failure_event'])) {
            $originalSecret = OAuthClient::findOrFail($input['client_id'])->secret;
            $originalRemember = auth()->user()->remember_token;
            AuditLog::creating(function (AuditLog $audit) use ($input, &$injection, $originalSecret, $originalRemember): void {
                if ($audit->event !== OAuthAuditEvent::from($input['failure_event'])
                    || (string) $audit->user_id !== (string) $input['actor_id']
                    || ($input['lifecycle'] === 'delete' ? $audit->client_id !== null : (string) $audit->client_id !== $input['client_id'])) {
                    return;
                }
                $injection['count']++;
                $injection['in_transaction'] = DB::transactionLevel() > 0;
                $client = OAuthClient::findOrFail($input['client_id']);
                $stateChanged = match ($input['lifecycle']) {
                    'rotate' => $client->secret !== $originalSecret,
                    'disconnect' => Consent::findOrFail($input['consent_id'])->revoked_at !== null,
                    'suspend' => $client->status === OAuthClientStatus::Suspended,
                    'delete' => ($target = User::findOrFail($input['actor_id']))->deletion_requested_at !== null
                        && $target->pending_email === null && $target->remember_token !== $originalRemember
                        && ! DB::table('sessions')->where('user_id', $target->id)->exists()
                        && ! DB::table('password_reset_tokens')->where('email', $target->email)->exists(),
                };
                $tokens = Passport::token()->newQuery();
                $codes = Passport::authCode()->newQuery();
                foreach ([$tokens, $codes] as $query) {
                    if ($input['lifecycle'] !== 'delete') {
                        $query->where('client_id', $input['client_id']);
                    }
                    if (in_array($input['lifecycle'], ['delete', 'disconnect'], true)) {
                        $query->where('user_id', $input['actor_id']);
                    }
                }
                $injection['mutations_observed'] = $stateChanged && ! (clone $tokens)->where('revoked', false)->exists()
                    && ! $codes->where('revoked', false)->exists()
                    && ! Passport::refreshToken()->newQuery()->whereIn('access_token_id', $tokens->select('id'))->where('revoked', false)->exists();
                throw new InjectedLifecycleFailure;
            });
        }
        try {
            match ($input['lifecycle']) {
                'rotate' => app(RegenerateApplicationSecret::class)->handle(OAuthClient::findOrFail($input['client_id'])),
                'disconnect' => app(DisconnectApp::class)->handle(auth()->user(), Consent::findOrFail($input['consent_id'])),
                'suspend' => app(SuspendApplication::class)->handle(OAuthClient::findOrFail($input['client_id'])),
                'delete' => app(RequestAccountDeletion::class)->handle(auth()->user()),
                default => throw new RuntimeException('Unknown lifecycle action.'),
            };
            $response = new Response('', 200);
        } catch (InjectedLifecycleFailure) {
            // Expected test failures never enter application diagnostics or HTTP handling.
            $injectedFailure = true;
            $response = new Response('', 500);
        } catch (Throwable $exception) {
            $application->make(ExceptionHandler::class)->report($exception);
            $response = new Response('', 500);
        }
    } else {
        $response = Bootstrap::request($application, $input['path'], $input['data']);
    }
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
        'identity_valid' => $identityValid, 'database_errors' => $errors,
        'injected_failure' => $injectedFailure, 'injection' => $injection, 'transaction_level' => DB::transactionLevel(),
        'notifications_empty' => Notification::sentNotifications() === [], 'queue_empty' => Queue::pushedJobs() === [],
        'transport' => isset($input['lifecycle']) ? 'policy_checked_action' : 'http_kernel']);
} catch (Throwable $exception) {
    concurrencyEvent(['type' => 'worker_failure', 'exception_class' => get_class($exception),
        'source_file' => basename($exception->getFile()), 'source_line' => $exception->getLine()]);
    exit(2);
}
