<?php

// Called only by the opt-in standalone coordinator after its isolation guards.
use App\Enums\OAuthClientStatus;
use App\Models\AuditLog;
use App\Models\Consent;
use App\Models\OAuthClient;
use App\Models\User;
use App\Services\OAuth\ReadToken;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Laravel\Passport\Passport;
use Tests\Support\Concurrency\Bootstrap;
use Tests\Support\Concurrency\WorkerProcess;

/** @return array<string, int> */
function lifecycleAudits(array $userIds, array $clientIds): array
{
    return AuditLog::where(function ($query) use ($userIds, $clientIds): void {
        $query->whereIn('user_id', $userIds)->orWhereIn('client_id', $clientIds);
    })->get()->groupBy('event')->map->count()->all();
}

/** @return array<string, mixed> */
function lifecycleFixture(array $configuration, string $issuance, string $lifecycle): array
{
    $fixture = concurrencyFixture($configuration, $issuance === 'code', $lifecycle === 'rotate');
    $target = User::findOrFail($fixture['user_id']);
    $owner = User::create(['name' => 'Lifecycle developer', 'email' => 'lifecycle-'.Str::uuid().'@example.test', 'password' => Str::random(48)]);
    $owner->forceFill(['email_verified_at' => now(), 'is_developer' => true])->save();
    OAuthClient::whereKey($fixture['client_id'])->update(['owner_type' => $owner->getMorphClass(), 'owner_id' => $owner->id]);
    $actor = $lifecycle === 'rotate' ? $owner : $target;
    if ($lifecycle === 'suspend') {
        $actor = User::create(['name' => 'Lifecycle administrator', 'email' => 'lifecycle-'.Str::uuid().'@example.test', 'password' => Str::random(48)]);
        $actor->forceFill(['email_verified_at' => now(), 'is_admin' => true,
            'two_factor_secret' => encrypt(Str::random(32)), 'two_factor_confirmed_at' => now()])->save();
    }
    // A fourth sentinel is outside both the target account and the target app.
    $unrelated = concurrencyIssue(concurrencyCode($owner, concurrencyClient(false))['data'])['access_token'];
    $fixture['sentinels'][] = $unrelated;
    $consent = Consent::where('user_id', $target->id)->where('client_id', $fixture['client_id'])->whereNull('revoked_at')->sole();
    $pending = concurrencyCode($target, OAuthClient::findOrFail($fixture['client_id']));
    // Confidential fixture models fetched again have no plaintext secret.
    $pending['data'] = array_replace($pending['data'], $fixture['credentials']);
    $userIds = [$target->id, $owner->id, $actor->id];
    $clientIds = [$fixture['client_id']];

    return [$fixture, $target, $actor, $consent, $pending, $userIds, $clientIds];
}

/** @return array<string, mixed> */
function lifecycleScenario(array $configuration, string $name, string $issuance, string $lifecycle, bool $lifecycleFirst): array
{
    [$fixture, $target, $actor, $consent, $pending, $userIds, $clientIds] = lifecycleFixture($configuration, $issuance, $lifecycle);
    $before = lifecycleAudits($userIds, $clientIds);
    $lifecycleInput = ['lifecycle' => $lifecycle, 'actor_id' => $actor->id, 'client_id' => $fixture['client_id'], 'consent_id' => $consent->id,
        'gate' => ['table' => $lifecycle === 'delete' ? 'users' : 'oauth_clients', 'operation' => 'select',
            'identifier' => $lifecycle === 'delete' ? $target->id : $fixture['client_id']]];
    $issuanceInput = concurrencyAction($fixture, $issuance, false);
    // Pause only after the serialization lock has actually been acquired.
    $issuanceInput['gate'] = ['table' => $lifecycle === 'delete' ? 'users' : 'oauth_clients', 'operation' => 'select',
        'identifier' => $lifecycle === 'delete' ? $target->id : $fixture['client_id']];
    [$firstInput, $secondInput] = $lifecycleFirst ? [$lifecycleInput, $issuanceInput] : [$issuanceInput, $lifecycleInput];
    $first = $second = null;
    try {
        $first = new WorkerProcess(['configuration' => $configuration, 'worker' => 'first', ...$firstInput]);
        $firstReady = $first->await('ready');
        $first->await('paused');
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
        $deadline = microtime(true) + 20;
        while ($second->event('result') === null) {
            if ($second->event('paused') !== null) {
                $second->send(['release' => 'second']);
                break;
            }
            if (microtime(true) >= $deadline) {
                throw new RuntimeException('Lifecycle second worker timed out.');
            }
            usleep(10000);
        }
        $secondResult = $second->await('result');
        [$lifecycleResult, $issuanceResult] = $lifecycleFirst ? [$firstResult, $secondResult] : [$secondResult, $firstResult];
        $tokens = Passport::token()->newQuery();
        $affected = match ($lifecycle) {
            'delete' => $tokens->where('user_id', $target->id),
            'disconnect' => $tokens->where('user_id', $target->id)->where('client_id', $fixture['client_id']),
            default => $tokens->where('client_id', $fixture['client_id']),
        };
        $activeAccess = (clone $affected)->where('revoked', false)->count();
        $activeRefresh = Passport::refreshToken()->newQuery()->where('revoked', false)->whereIn('access_token_id', (clone $affected)->select('id'))->count();
        $codes = Passport::authCode()->newQuery();
        $affectedCodes = match ($lifecycle) {
            'delete' => $codes->where('user_id', $target->id),
            'disconnect' => $codes->where('user_id', $target->id)->where('client_id', $fixture['client_id']),
            default => $codes->where('client_id', $fixture['client_id']),
        };
        // Invalid old-secret authentication alone cannot prove pending codes were revoked.
        $activeCodes = $affectedCodes->where('revoked', false)->count();
        $expectedSentinels = match ($lifecycle) {
            'rotate', 'suspend' => [false, false, true, true],
            'disconnect' => [false, true, true, true],
            'delete' => [false, true, false, true],
        };
        $sentinels = array_map('concurrencyBearerValid', $fixture['sentinels']);
        $sentinelRefresh = array_map(function (string $token): bool {
            $accessId = app(ReadToken::class)->access($token);

            return Passport::refreshToken()->newQuery()->where('access_token_id', $accessId)->where('revoked', false)->exists();
        }, $fixture['sentinels']);
        $audits = lifecycleAudits($userIds, $clientIds);
        foreach ($before as $event => $count) {
            $audits[$event] -= $count;
        }
        $audits = array_filter($audits);
        $lifecycleEvent = match ($lifecycle) {
            'rotate' => 'client.secret_regenerated', 'disconnect' => 'consent.revoked',
            'suspend' => 'client.suspended', 'delete' => 'account.deletion_requested',
        };
        $auditValid = ($audits[$lifecycleEvent] ?? 0) === 1
            && ($audits[$issuance === 'code' ? 'token.issued' : 'token.refreshed'] ?? 0) === ($lifecycleFirst ? 0 : 1);
        $client = OAuthClient::findOrFail($fixture['client_id']);
        $stateValid = match ($lifecycle) {
            'rotate' => ! Hash::check($fixture['credentials']['client_secret'], $client->secret),
            'disconnect' => $consent->fresh()->revoked_at !== null,
            'suspend' => $client->status === OAuthClientStatus::Suspended,
            'delete' => $target->fresh()->deletion_requested_at !== null && $target->fresh()->deletion_due_at !== null,
        };
        // Verify a second pre-existing code cannot issue after the committed transition.
        $post = Bootstrap::request(app(), '/oauth/token', $pending['data']);
        $postPayload = json_decode($post->getContent(), true);
        $expectedError = in_array($lifecycle, ['rotate', 'suspend'], true) ? 'invalid_client' : 'invalid_grant';
        $expectedStatus = $expectedError === 'invalid_client' ? 401 : 400;
        $postRejected = $post->getStatusCode() === $expectedStatus && ($postPayload['error'] ?? null) === $expectedError && ! isset($postPayload['access_token']);
        $freshAuthorization = null;
        if ($lifecycle === 'disconnect' && $lifecycleResult['status'] === 200) {
            $freshAuthorization = concurrencyBearerValid(concurrencyIssue(concurrencyCode($target, $client)['data'])['access_token']);
        }
        $results = [$firstResult, $secondResult];
        $errors = collect($results)->flatMap(fn (array $result): array => $result['database_errors']);
        $deadlock = $errors->contains(fn (array $error): bool => $error['vendor_code'] === 1213 && $error['sqlstate'] === '40001');
        $expected = $lifecycleResult['status'] === 200
            && ($lifecycleFirst ? $issuanceResult['status'] === $expectedStatus && $issuanceResult['oauth_error'] === $expectedError : $issuanceResult['status'] === 200)
            && $activeAccess === 0 && $activeRefresh === 0 && $activeCodes === 0
            && $sentinels === $expectedSentinels && $sentinelRefresh === $expectedSentinels
            && $stateValid && $auditValid && $postRejected && $freshAuthorization !== false
            && $errors->isEmpty() && $wait['observed'] && $wait['requested_table'] === $lifecycleInput['gate']['table']
            && $issuanceResult['identity_valid'] === ($lifecycleFirst ? null : true);

        return ['scenario' => $name, 'classification' => $deadlock ? 'confirmed_deadlock' : ($expected ? 'passed' : 'needs_review'),
            'issuance' => $issuance, 'lifecycle' => $lifecycle, 'lifecycle_first' => $lifecycleFirst,
            'connection_ids' => [$firstReady['connection'], $secondReady['connection']], 'lock_wait' => $wait, 'results' => $results,
            'active_affected_access' => $activeAccess, 'active_affected_refresh' => $activeRefresh,
            'active_affected_codes' => $activeCodes, 'sentinels' => $sentinels, 'sentinel_refresh_active' => $sentinelRefresh,
            'expected_sentinels' => $expectedSentinels, 'state_valid' => $stateValid,
            'audits' => $audits, 'audit_valid' => $auditValid, 'post_transition_rejected' => $postRejected,
            'post_transition_status' => $post->getStatusCode(), 'fresh_explicit_authorization_valid' => $freshAuthorization];
    } finally {
        $first?->close();
        $second?->close();
    }
}
