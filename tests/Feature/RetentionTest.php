<?php

use App\Actions\Maintenance\PruneRetainedRecords;
use App\Enums\OAuthAuditEvent;
use App\Enums\RetentionCategory;
use App\Models\AuditLog;
use App\Models\OAuthClient;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schedule;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    $this->freezeTime();
    config(['session.driver' => 'database', 'session.connection' => null, 'session.table' => 'sessions',
        'queue.failed.driver' => 'database-uuids', 'queue.failed.database' => config('database.default'),
        'queue.failed.table' => 'failed_jobs']);
});

/** @return array{access: string, refresh: string, family: string, user: User, client: OAuthClient} */
function retentionCredential(?User $user = null, ?OAuthClient $client = null, ?string $family = null): array
{
    $user ??= User::factory()->create();
    $client ??= oauthClientFixture();
    $family ??= Str::random(80);
    $access = Str::random(80);
    $refresh = Str::random(80);
    DB::table('oauth_access_tokens')->insert(['id' => $access, 'client_id' => $client->id, 'user_id' => $user->id,
        'auth_code_id' => $family, 'scopes' => '[]', 'revoked' => true, 'expires_at' => now()->subDays(31)]);
    DB::table('oauth_refresh_tokens')->insert(['id' => $refresh, 'access_token_id' => $access,
        'revoked' => true, 'expires_at' => now()->subDays(31)]);

    return compact('access', 'refresh', 'family', 'user', 'client');
}

function retentionAudit(string $age = '-366 days'): AuditLog
{
    $audit = AuditLog::create(['event' => OAuthAuditEvent::LoginFailed]);
    $audit->forceFill(['created_at' => now()->modify($age)])->save();

    return $audit;
}

it('previews all approved categories without deleting records or changing checkpoints', function (): void {
    $audit = retentionAudit();
    $pair = retentionCredential();
    DB::table('sessions')->insert(['id' => 'private-session', 'payload' => 'private-payload', 'last_activity' => now()->subHours(3)->timestamp]);
    DB::table('password_reset_tokens')->insert(['email' => 'private@example.test', 'token' => 'private-reset', 'created_at' => now()->subHours(2)]);
    DB::table('failed_jobs')->insert(['uuid' => Str::uuid(), 'connection' => 'database', 'queue' => 'default',
        'payload' => 'private-job', 'exception' => 'private-exception', 'failed_at' => now()->subDays(31)]);
    Cache::shouldReceive('get')->times(6)->andReturn(null);
    Cache::shouldNotReceive('put');
    Cache::shouldNotReceive('forget');
    Cache::shouldNotReceive('lock');
    $report = app(PruneRetainedRecords::class)->handle(RetentionCategory::cases());
    expect($report['audit']['eligible'])->toBe(1)->and($report['oauth']['eligible'])->toBe(2)
        ->and($report['sessions']['eligible'])->toBe(1)->and($report['resets']['eligible'])->toBe(1)
        ->and($report['failed-jobs']['eligible'])->toBe(1);
    expect(AuditLog::find($audit->id))->not->toBeNull()->and(DB::table('oauth_refresh_tokens')->where('id', $pair['refresh'])->exists())->toBeTrue();
    expect(DB::table('sessions')->count())->toBe(1)->and(DB::table('password_reset_tokens')->count())->toBe(1)->and(DB::table('failed_jobs')->count())->toBe(1);
});

it('uses strict cutoff boundaries for audit sessions resets and failed jobs', function (): void {
    $old = retentionAudit();
    $boundary = retentionAudit('-365 days');
    $fresh = retentionAudit('-364 days');
    foreach (['old' => -1, 'boundary' => 0, 'fresh' => 1] as $label => $offset) {
        DB::table('sessions')->insert(['id' => $label, 'payload' => 'private', 'last_activity' => now()->subMinutes(120)->addSeconds($offset)->timestamp]);
        DB::table('password_reset_tokens')->insert(['email' => $label.'@example.test', 'token' => 'private', 'created_at' => now()->subMinutes(60)->addSeconds($offset)]);
        DB::table('failed_jobs')->insert(['uuid' => Str::uuid(), 'connection' => 'database', 'queue' => 'default',
            'payload' => 'private', 'exception' => 'private', 'failed_at' => now()->subDays(30)->addSeconds($offset)]);
    }
    $report = app(PruneRetainedRecords::class)->handle([RetentionCategory::Audit, RetentionCategory::Sessions, RetentionCategory::Resets, RetentionCategory::FailedJobs], true);
    foreach ($report as $category) {
        expect($category['deleted'])->toBe(1);
    }
    expect(AuditLog::find($old->id))->toBeNull()->and(AuditLog::whereKey([$boundary->id, $fresh->id])->count())->toBe(2);
    expect(DB::table('sessions')->pluck('id')->all())->toEqualCanonicalizing(['boundary', 'fresh']);
    expect(DB::table('password_reset_tokens')->count())->toBe(2)->and(DB::table('failed_jobs')->count())->toBe(2);
});

it('bounds each scan and deletion and advances past retained rows across executions', function (): void {
    config(['retention.scan_limit' => 2, 'retention.delete_limit' => 1]);
    $retained = retentionAudit('-1 day');
    $first = retentionAudit();
    $second = retentionAudit();
    $action = app(PruneRetainedRecords::class);
    $report = $action->handle([RetentionCategory::Audit], true)['audit'];
    expect($report['scanned'])->toBe(2)->and($report['deleted'])->toBe(1);
    $report = $action->handle([RetentionCategory::Audit], true)['audit'];
    expect($report['scanned'])->toBe(1)->and($report['deleted'])->toBe(1);
    $action->handle([RetentionCategory::Audit], true); // End of scan resets the cursor.
    expect($action->handle([RetentionCategory::Audit], true)['audit']['deleted'])->toBe(0);
    expect(AuditLog::find($retained->id))->not->toBeNull()->and(AuditLog::find($first->id))->toBeNull()->and(AuditLog::find($second->id))->toBeNull();
});

it('prunes expired families refresh before access and never changes unrelated history', function (): void {
    $pair = retentionCredential();
    $other = retentionCredential();
    DB::table('oauth_refresh_tokens')->where('id', $other['refresh'])->update(['expires_at' => now()->addDay()]);
    $queries = [];
    DB::listen(function ($query) use (&$queries): void {
        if (str_starts_with($query->sql, 'delete')) {
            $queries[] = $query->sql;
        }
    });
    $report = app(PruneRetainedRecords::class)->handle([RetentionCategory::OAuth], true)['oauth'];
    expect($report['deleted'])->toBe(2)->and($report['deferred'])->toBe(1);
    expect($queries[0])->toContain('oauth_refresh_tokens')->and($queries[1])->toContain('oauth_access_tokens');
    expect(DB::table('oauth_access_tokens')->where('id', $pair['access'])->exists())->toBeFalse()
        ->and(DB::table('oauth_refresh_tokens')->where('id', $other['refresh'])->exists())->toBeTrue();
    expect(User::count())->toBe(2)->and(DB::table('oauth_clients')->count())->toBe(2);
});

it('preserves every ancestor while any family member has live recent or unknown expiry', function (string $protected): void {
    $pair = retentionCredential();
    $successor = retentionCredential($pair['user'], $pair['client'], $pair['family']);
    $expiry = match ($protected) {
        'live' => now()->addDay(), 'recent' => now()->subDays(29), 'boundary' => now()->subDays(30), 'unknown' => null,
        // Strict MySQL rejects zero dates on write; exercise the same fail-closed
        // pre-epoch branch there while SQLite also covers legacy zero-date data.
        'zero' => DB::getDriverName() === 'mysql' ? '1969-12-31 23:59:59' : '0000-00-00 00:00:00',
    };
    DB::table('oauth_refresh_tokens')->where('id', $successor['refresh'])->update(['expires_at' => $expiry]);
    app(PruneRetainedRecords::class)->handle([RetentionCategory::OAuth], true);
    expect(DB::table('oauth_access_tokens')->count())->toBe(2)->and(DB::table('oauth_refresh_tokens')->count())->toBe(2);
})->with(['live', 'recent', 'boundary', 'unknown', 'zero']);

it('does not merge colliding family references across accounts or clients', function (): void {
    $pair = retentionCredential();
    $otherUser = retentionCredential(client: $pair['client'], family: $pair['family']);
    $otherClient = retentionCredential($pair['user'], family: $pair['family']);
    DB::table('oauth_refresh_tokens')->whereIn('id', [$otherUser['refresh'], $otherClient['refresh']])->update(['expires_at' => now()->addDay()]);
    app(PruneRetainedRecords::class)->handle([RetentionCategory::OAuth], true);
    expect(DB::table('oauth_access_tokens')->where('id', $pair['access'])->exists())->toBeFalse()
        ->and(DB::table('oauth_access_tokens')->count())->toBe(2);
});

it('bounds large eligible family deletion and converges on later runs', function (): void {
    config(['retention.delete_limit' => 2]);
    $pair = retentionCredential();
    retentionCredential($pair['user'], $pair['client'], $pair['family']);
    $action = app(PruneRetainedRecords::class);
    expect($action->handle([RetentionCategory::OAuth], true)['oauth']['deleted'])->toBe(2);
    for ($run = 0; $run < 3; $run++) {
        $action->handle([RetentionCategory::OAuth], true);
    }
    expect(DB::table('oauth_access_tokens')->count())->toBe(0)->and(DB::table('oauth_refresh_tokens')->count())->toBe(0);
});

it('advances checkpoints beyond deferred families when the family work cap is reached', function (): void {
    config(['retention.family_limit' => 1]);
    for ($number = 0; $number < 3; $number++) {
        $pair = retentionCredential();
        DB::table('oauth_refresh_tokens')->where('id', $pair['refresh'])->update(['expires_at' => now()->addDay()]);
    }
    $scans = [];
    for ($run = 0; $run < 3; $run++) {
        $scans[] = app(PruneRetainedRecords::class)->handle([RetentionCategory::OAuth], true)['oauth']['deferred'];
    }
    expect($scans)->toBe([1, 1, 1]);
});

it('skips missing owners null expiry and ambiguous legacy lineage without deleting evidence', function (string $invalid): void {
    $pair = retentionCredential();
    match ($invalid) {
        'owner' => DB::table('users')->where('id', $pair['user']->id)->delete(),
        'client' => DB::table('oauth_clients')->where('id', $pair['client']->id)->delete(),
        'expiry' => DB::table('oauth_access_tokens')->where('id', $pair['access'])->update(['expires_at' => null]),
        'lineage' => DB::table('oauth_access_tokens')->where('id', $pair['access'])->update(['auth_code_id' => null]),
    };
    $report = app(PruneRetainedRecords::class)->handle([RetentionCategory::OAuth], true)['oauth'];
    expect($report['invalid'])->toBe(1)->and($report['deleted'])->toBe(0);
    expect(DB::table('oauth_refresh_tokens')->count())->toBe(1);
})->with(['owner', 'client', 'expiry', 'lineage']);

it('cleans unambiguous expired machine credentials but preserves their live refresh records', function (): void {
    $pair = retentionCredential();
    $pair['client']->forceFill(['grant_types' => ['client_credentials']])->save();
    DB::table('oauth_access_tokens')->where('id', $pair['access'])->update(['user_id' => null, 'auth_code_id' => null]);
    DB::table('oauth_refresh_tokens')->where('id', $pair['refresh'])->update(['expires_at' => now()->addDay()]);
    $action = app(PruneRetainedRecords::class);
    expect($action->handle([RetentionCategory::OAuth], true)['oauth']['deleted'])->toBe(0);
    DB::table('oauth_refresh_tokens')->where('id', $pair['refresh'])->update(['expires_at' => now()->subDays(31)]);
    $action->handle([RetentionCategory::OAuth], true); // reset cursor
    expect($action->handle([RetentionCategory::OAuth], true)['oauth']['deleted'])->toBe(2);
});

it('removes only old codes while retaining access lineage and recent revoked codes', function (): void {
    $pair = retentionCredential();
    foreach (['old' => now()->subDays(31), 'recent' => now()->addMinute()] as $id => $expiry) {
        DB::table('oauth_auth_codes')->insert(['id' => $id, 'client_id' => $pair['client']->id, 'user_id' => $pair['user']->id,
            'scopes' => '[]', 'revoked' => true, 'expires_at' => $expiry]);
    }
    expect(app(PruneRetainedRecords::class)->handle([RetentionCategory::Codes], true)['codes']['deleted'])->toBe(1);
    expect(DB::table('oauth_auth_codes')->pluck('id')->all())->toBe(['recent']);
    expect(DB::table('oauth_access_tokens')->value('auth_code_id'))->toBe($pair['family']);
});

it('rechecks family eligibility after client and owner serialization', function (): void {
    $pair = retentionCredential();
    $changed = false;
    $order = [];
    DB::listen(function ($query) use ($pair, &$changed, &$order): void {
        if (! str_starts_with($query->sql, 'select')) {
            return;
        }
        if (str_contains($query->sql, 'oauth_clients')) {
            $order[] = 'client';
            expect(DB::transactionLevel())->toBeGreaterThan(0);
            if (! $changed) {
                $changed = true;
                DB::table('oauth_refresh_tokens')->where('id', $pair['refresh'])->update(['expires_at' => now()->addDay()]);
            }
        } elseif (str_contains(str_replace(['`', '"'], '', $query->sql), 'from users')) {
            $order[] = 'owner';
        }
    });
    expect(app(PruneRetainedRecords::class)->handle([RetentionCategory::OAuth], true)['oauth']['deleted'])->toBe(0);
    expect(array_slice($order, 0, 2))->toBe(['client', 'owner']);
});

it('rolls back paired deletion and leaves its checkpoint unchanged on storage failure', function (): void {
    $pair = retentionCredential();
    $fail = true;
    DB::listen(function ($query) use (&$fail): void {
        if ($fail && str_starts_with(str_replace(['`', '"'], '', $query->sql), 'delete from oauth_refresh_tokens')) {
            $fail = false;
            throw new RuntimeException('Synthetic deletion failure');
        }
    });
    expect(fn () => app(PruneRetainedRecords::class)->handle([RetentionCategory::OAuth], true))->toThrow(RuntimeException::class);
    expect(DB::table('oauth_access_tokens')->count())->toBe(1)->and(DB::table('oauth_refresh_tokens')->count())->toBe(1);
    expect(app(PruneRetainedRecords::class)->handle([RetentionCategory::OAuth], true)['oauth']['deleted'])->toBe(2);
});

it('keeps refresh replay detection working after retention runs', function (): void {
    $user = User::factory()->create();
    $client = oauthClientFixture();
    $original = $this->postJson('/oauth/token', oauthExchange($client, oauthCode($this, $user, $client)))->assertOk()->json();
    $parameters = ['grant_type' => 'refresh_token', 'client_id' => $client->id];
    $successor = $this->postJson('/oauth/token', $parameters + ['refresh_token' => $original['refresh_token']])->assertOk()->json();
    DB::table('oauth_access_tokens')->where('revoked', true)->update(['expires_at' => now()->subDays(31)]);
    app(PruneRetainedRecords::class)->handle([RetentionCategory::OAuth], true);
    expect(oauthBearerWorks($successor['access_token']))->toBeTrue();
    $this->postJson('/oauth/token', $parameters + ['refresh_token' => $original['refresh_token']])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
    expect(oauthBearerWorks($successor['access_token']))->toBeFalse()->and(AuditLog::where('event', OAuthAuditEvent::RefreshReplayed)->count())->toBe(1);
});

it('rejects unsupported stores and invalid limits before deleting any selected category', function (string $setting): void {
    retentionAudit();
    match ($setting) {
        'sessions' => config(['session.driver' => 'redis']),
        'reset' => config(['auth.passwords.users.driver' => 'cache']),
        'failed' => config(['queue.failed.driver' => 'null']),
        'limit' => config(['retention.delete_limit' => 0]),
        'connection' => config(['session.connection' => 'unapproved']),
    };
    expect(fn () => app(PruneRetainedRecords::class)->handle(RetentionCategory::cases(), true))->toThrow(RuntimeException::class);
    expect(AuditLog::count())->toBe(1);
})->with(['sessions', 'reset', 'failed', 'limit', 'connection']);

it('keeps console output aggregate only and requires the explicit execution flag', function (): void {
    $audit = retentionAudit();
    $this->artisan('retention:prune', ['--only' => ['audit']])->expectsOutput('Preview only. No records or checkpoints changed.')->assertSuccessful();
    expect(AuditLog::find($audit->id))->not->toBeNull();
    $this->artisan('retention:prune', ['--only' => ['audit'], '--execute' => true])->assertSuccessful();
    expect(AuditLog::find($audit->id))->toBeNull();
    $this->artisan('retention:prune', ['--only' => ['invalid']])->assertFailed();
});

it('keeps scheduled cleanup disabled until rollout approval', function (): void {
    $events = collect(Schedule::events())->filter(fn ($event): bool => str_contains($event->command ?? '', 'retention:prune'));
    expect($events)->toHaveCount(2)->and(config('retention.scheduled_enabled'))->toBeFalse();
    foreach ($events as $event) {
        expect($event->onOneServer)->toBeTrue()->and($event->withoutOverlapping)->toBeTrue()->and($event->filtersPass(app()))->toBeFalse();
    }
});

it('preserves a renewed session or reset link when expiry changes immediately before deletion', function (string $category): void {
    $table = $category === 'sessions' ? 'sessions' : 'password_reset_tokens';
    if ($category === 'sessions') {
        DB::table($table)->insert(['id' => 'synthetic-session', 'payload' => 'private', 'last_activity' => now()->subHours(3)->timestamp]);
    } else {
        DB::table($table)->insert(['email' => 'synthetic@example.test', 'token' => 'private', 'created_at' => now()->subHours(2)]);
    }
    $renewed = false;
    DB::connection()->beforeExecuting(function ($sql) use ($table, $category, &$renewed): void {
        if (! $renewed && str_starts_with($sql, 'delete') && str_contains($sql, $table)) {
            $renewed = true;
            DB::table($table)->update($category === 'sessions' ? ['last_activity' => now()->timestamp] : ['created_at' => now()]);
        }
    });
    $report = app(PruneRetainedRecords::class)->handle([RetentionCategory::from($category)], true)[$category];
    expect($report['eligible'])->toBe(1)->and($report['deleted'])->toBe(0)->and(DB::table($table)->count())->toBe(1);
})->with(['sessions', 'resets']);

it('keeps the backing access row until all expired attached refresh records are removed', function (): void {
    config(['retention.delete_limit' => 1]);
    $pair = retentionCredential();
    $action = app(PruneRetainedRecords::class);
    expect($action->handle([RetentionCategory::OAuth], true)['oauth']['deleted'])->toBe(1);
    expect(DB::table('oauth_access_tokens')->count())->toBe(1)->and(DB::table('oauth_refresh_tokens')->count())->toBe(0);
    $action->handle([RetentionCategory::OAuth], true); // Cursor wraps.
    expect($action->handle([RetentionCategory::OAuth], true)['oauth']['deleted'])->toBe(1);
});

it('does not delete or advance when another cleanup owns the execution lock', function (): void {
    retentionAudit();
    $lock = Cache::lock('retention:prune', 600);
    expect($lock->get())->toBeTrue();
    try {
        expect(fn () => app(PruneRetainedRecords::class)->handle([RetentionCategory::Audit], true))->toThrow(RuntimeException::class);
        expect(AuditLog::count())->toBe(1);
    } finally {
        $lock->release();
    }
});

it('encrypts execution checkpoints instead of exposing session references in the cache', function (): void {
    DB::table('sessions')->insert(['id' => 'synthetic-private-session-id', 'payload' => 'private', 'last_activity' => now()->timestamp]);
    app(PruneRetainedRecords::class)->handle([RetentionCategory::Sessions], true);
    $key = 'retention:cursor:'.hash('sha256', DB::connection()->getDatabaseName().':sessions');
    $stored = Cache::get($key);
    expect($stored)->not->toContain('synthetic-private-session-id');
    expect(Crypt::decryptString($stored))->toBe('synthetic-private-session-id');
});

it('reports only fixed safe text on command failures', function (): void {
    $action = Mockery::mock(PruneRetainedRecords::class);
    $action->shouldReceive('handle')->once()->andThrow(new RuntimeException('synthetic-sensitive-value'));
    app()->instance(PruneRetainedRecords::class, $action);
    expect(Artisan::call('retention:prune', ['--only' => ['audit']]))->toBe(1);
    expect(Artisan::output())->toContain('Retention cleanup could not complete.')->not->toContain('synthetic-sensitive-value');
});
