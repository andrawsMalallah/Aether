<?php

// Snapshots are private coordinator memory; only comparison booleans reach reports.
use App\Models\OAuthClient;
use App\Models\User;
use App\Services\OAuth\ReadToken;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Laravel\Passport\Passport;
use Tests\Support\Concurrency\Bootstrap;
use Tests\Support\Concurrency\WorkerProcess;

/** @return array<string, array> */
function rollbackSnapshot(array $userIds, array $clientIds): array
{
    $scope = function ($query) use ($userIds, $clientIds): void {
        $query->whereIn('user_id', $userIds)->orWhereIn('client_id', $clientIds);
    };
    $access = DB::table('oauth_access_tokens')->where($scope);
    $emails = DB::table('users')->whereIn('id', $userIds)->pluck('email');
    $queries = [
        'users' => DB::table('users')->whereIn('id', $userIds)->select('id', 'deletion_requested_at', 'deletion_due_at', 'pending_email', 'pending_email_requested_at', 'remember_token', 'updated_at')->orderBy('id'),
        'clients' => DB::table('oauth_clients')->whereIn('id', $clientIds)->select('id', 'secret', 'status', 'revoked', 'updated_at')->orderBy('id'),
        'consents' => DB::table('consents')->where($scope)->select('id', 'user_id', 'client_id', 'scopes', 'revoked_at', 'updated_at')->orderBy('id'),
        'codes' => DB::table('oauth_auth_codes')->where($scope)->select('id', 'revoked', 'scopes', 'expires_at')->orderBy('id'),
        'access' => (clone $access)->select('id', 'revoked', 'scopes', 'auth_code_id', 'expires_at')->orderBy('id'),
        'refresh' => DB::table('oauth_refresh_tokens')->whereIn('access_token_id', (clone $access)->select('id'))->select('id', 'access_token_id', 'revoked', 'expires_at')->orderBy('id'),
        'sessions' => DB::table('sessions')->whereIn('user_id', $userIds)->select('id', 'user_id', 'payload', 'last_activity')->orderBy('id'),
        'reset_links' => DB::table('password_reset_tokens')->whereIn('email', $emails)->select('email', 'token', 'created_at')->orderBy('email'),
        'audits' => DB::table('audit_logs')->where($scope)->select('id', 'user_id', 'client_id', 'event')->orderBy('id'),
    ];

    return array_map(fn ($query): array => $query->get()->map(fn (object $row): array => (array) $row)->all(), $queries);
}

/** @return array<string, bool> */
function rollbackComparisons(array $baseline, array $current): array
{
    $comparisons = [];
    foreach ($baseline as $group => $rows) {
        $comparisons[$group] = $rows === $current[$group];
    }

    return $comparisons;
}

/** @return array{status: int, valid: bool} */
function rollbackCodeProbe(array $data): array
{
    $response = Bootstrap::request(app(), '/oauth/token', $data);
    $payload = json_decode($response->getContent(), true);

    return ['status' => $response->getStatusCode(), 'valid' => $response->getStatusCode() === 200
        && is_string($payload['access_token'] ?? null) && concurrencyBearerValid($payload['access_token'])];
}

/** @return array<string, mixed> */
function rollbackScenario(array $configuration, string $name, string $issuance, string $lifecycle, bool $lifecycleFirst): array
{
    [$fixture, $target, $actor, $consent, $pending, $userIds, $clientIds] = lifecycleFixture($configuration, $issuance, $lifecycle);
    $sentinelIds = array_map(fn (string $token): string => app(ReadToken::class)->access($token), $fixture['sentinels']);
    $sentinelRows = Passport::token()->newQuery()->whereIn('id', $sentinelIds)->get(['user_id', 'client_id']);
    $userIds = array_values(array_unique([...$userIds, ...$sentinelRows->pluck('user_id')->all()]));
    $clientIds = array_values(array_unique([...$clientIds, ...$sentinelRows->pluck('client_id')->all()]));
    $unrelated = Passport::token()->newQuery()->findOrFail(end($sentinelIds));
    $unrelatedPending = concurrencyCode(User::findOrFail($unrelated->user_id), OAuthClient::findOrFail($unrelated->client_id));
    if ($lifecycle === 'delete') {
        // Make rollback of deletion's actual DELETE/UPDATE operations observable.
        foreach ([$target, User::findOrFail($unrelated->user_id)] as $sessionOwner) {
            $sessionOwner->forceFill(['remember_token' => Str::random(60), 'pending_email' => 'pending-'.Str::uuid().'@example.test', 'pending_email_requested_at' => now()])->save();
            DB::table('sessions')->insert(['id' => Str::random(64), 'user_id' => $sessionOwner->id,
                'payload' => base64_encode(serialize(['synthetic' => true])), 'last_activity' => time()]);
            DB::table('password_reset_tokens')->insert(['email' => $sessionOwner->email, 'token' => hash('sha256', Str::random(64)), 'created_at' => now()]);
        }
    }
    $event = match ($lifecycle) {
        'rotate' => 'client.secret_regenerated', 'disconnect' => 'consent.revoked',
        'suspend' => 'client.suspended', 'delete' => 'account.deletion_requested',
    };
    $before = lifecycleAudits($userIds, $clientIds);
    $gate = ['table' => $lifecycle === 'delete' ? 'users' : 'oauth_clients', 'operation' => 'select',
        'identifier' => $lifecycle === 'delete' ? $target->id : $fixture['client_id']];
    $lifecycleInput = ['lifecycle' => $lifecycle, 'failure_event' => $event, 'actor_id' => $actor->id,
        'client_id' => $fixture['client_id'], 'consent_id' => $consent->id, 'gate' => $gate];
    $issuanceInput = concurrencyAction($fixture, $issuance, false);
    $issuanceInput['gate'] = $gate;
    [$firstInput, $secondInput] = $lifecycleFirst ? [$lifecycleInput, $issuanceInput] : [$issuanceInput, $lifecycleInput];
    $first = $second = null;
    try {
        $first = new WorkerProcess(['configuration' => $configuration, 'worker' => 'first', ...$firstInput]);
        $firstReady = $first->await('ready');
        $first->await('paused');
        $baseline = $lifecycleFirst ? rollbackSnapshot($userIds, $clientIds) : null;
        $second = new WorkerProcess(['configuration' => $configuration, 'worker' => 'second', ...$secondInput]);
        $secondReady = $second->await('ready');
        $deadline = microtime(true) + 5;
        do {
            $wait = concurrencyWait(DB::connection()->getPdo(), Bootstrap::databaseName($configuration['run_id']), $secondReady['connection'], $firstReady['connection']);
            if ($wait['observed'] || ! $wait['available']) {
                break;
            }
            usleep(10000);
        } while (microtime(true) < $deadline);
        $first->send(['release' => 'first']);
        $firstResult = $first->await('result');
        $second->await('paused');
        if ($lifecycleFirst) {
            // Issuance now holds its lock but has not mutated credentials yet.
            $comparisons = rollbackComparisons($baseline, rollbackSnapshot($userIds, $clientIds));
        } else {
            // Successful issuance belongs in the baseline, including normal rotation.
            $baseline = rollbackSnapshot($userIds, $clientIds);
        }
        $second->send(['release' => 'second']);
        $secondResult = $second->await('result');
        if (! $lifecycleFirst) {
            $comparisons = rollbackComparisons($baseline, rollbackSnapshot($userIds, $clientIds));
        }
        [$failed, $issued] = $lifecycleFirst ? [$firstResult, $secondResult] : [$secondResult, $firstResult];
        $audits = lifecycleAudits($userIds, $clientIds);
        foreach ($before as $auditEvent => $count) {
            $audits[$auditEvent] -= $count;
        }
        $audits = array_filter($audits);
        $auditValid = $audits === [$issuance === 'code' ? 'token.issued' : 'token.refreshed' => 1];
        $sentinelsValid = ! in_array(false, array_map('concurrencyBearerValid', $fixture['sentinels']), true);
        $sentinelRefreshValid = Passport::refreshToken()->newQuery()->whereIn('access_token_id', $sentinelIds)->where('revoked', false)->count() === count($sentinelIds);
        $family = Passport::token()->newQuery()->where('auth_code_id', $fixture['family']);
        $familyValid = (clone $family)->where('revoked', false)->count() === 1
            && Passport::refreshToken()->newQuery()->whereIn('access_token_id', $family->select('id'))->where('revoked', false)->count() === 1;
        $injectionValid = $failed['injected_failure'] && $failed['injection'] === ['count' => 1, 'in_transaction' => true, 'mutations_observed' => true]
            && $failed['status'] === 500 && $failed['transaction_level'] === 0 && $failed['notifications_empty'] && $failed['queue_empty'];
        $results = [$firstResult, $secondResult];
        $errors = collect($results)->flatMap(fn (array $result): array => $result['database_errors']);
        $deadlock = $errors->contains(fn (array $error): bool => $error['vendor_code'] === 1213 && $error['sqlstate'] === '40001');
        // These probes occur after snapshots/audit deltas, and never replay spent pairs.
        $pendingProbe = rollbackCodeProbe($pending['data']);
        $unrelatedPendingProbe = rollbackCodeProbe($unrelatedPending['data']);
        $expected = $injectionValid && $issued['status'] === 200 && $issued['identity_valid'] === true
            && ! $issued['injected_failure'] && $issued['transaction_level'] === 0
            && ! in_array(false, $comparisons, true) && $auditValid && $sentinelsValid && $sentinelRefreshValid
            && $familyValid && $pendingProbe['valid'] && $unrelatedPendingProbe['valid'] && $errors->isEmpty()
            && $wait['observed'] && $wait['requested_table'] === $gate['table'];

        return ['scenario' => $name, 'classification' => $deadlock ? 'confirmed_deadlock' : ($expected ? 'passed' : 'needs_review'),
            'issuance' => $issuance, 'lifecycle' => $lifecycle, 'lifecycle_first' => $lifecycleFirst,
            'connection_ids' => [$firstReady['connection'], $secondReady['connection']], 'lock_wait' => $wait, 'results' => $results,
            'rollback_comparisons' => $comparisons, 'injection_valid' => $injectionValid, 'audits' => $audits, 'audit_valid' => $auditValid,
            'sentinels_valid' => $sentinelsValid, 'sentinel_refresh_valid' => $sentinelRefreshValid, 'issued_family_valid' => $familyValid,
            'pending_code_probe' => $pendingProbe, 'unrelated_pending_code_probe' => $unrelatedPendingProbe];
    } finally {
        $first?->close();
        $second?->close();
    }
}
