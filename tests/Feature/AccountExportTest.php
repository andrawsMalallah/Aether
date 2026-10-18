<?php

use App\Actions\Account\ListAccountExports;
use App\Actions\Account\PruneAccountExports;
use App\Actions\Account\RequestAccountExport;
use App\Enums\AccountExportStatus;
use App\Enums\OAuthAuditEvent;
use App\Jobs\GenerateAccountExport;
use App\Models\AccountExport;
use App\Models\AuditLog;
use App\Models\Consent;
use App\Models\User;
use App\Notifications\AccountExportReady;
use App\Policies\AccountExportPolicy;
use App\Services\AccountExportWriter;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Notifications\ChannelManager;
use Illuminate\Notifications\SendQueuedNotifications;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    Storage::fake('local');
    Notification::fake();
    $this->realQueue = Queue::getFacadeRoot();
    Queue::fake();
    $this->owner = User::factory()->create();
});

function accountExportFixture(User $owner, AccountExportStatus $status = AccountExportStatus::Pending): AccountExport
{
    return AccountExport::create(['user_id' => $owner->id, 'status' => $status, 'expires_at' => now()->addDay(),
        'completed_at' => $status === AccountExportStatus::Ready ? now() : null]);
}

it('requires verified ownership recent password and explicit confirmation on export requests', function (): void {
    $this->get('/account/export')->assertRedirect('/login');
    $this->post('/account/export', ['confirm' => true])->assertRedirect('/login');
    $this->actingAs(User::factory()->unverified()->create())->get('/account/export')->assertRedirect('/email/verify');
    $this->actingAs($this->owner)->get('/account/export')->assertRedirect('/account/confirm-password');
    $this->withSession(['auth.password_confirmed_at' => now()->timestamp])->post('/account/export')->assertSessionHasErrors('confirm');
    expect(AccountExport::count())->toBe(0);
    $this->post('/account/export', ['confirm' => true])->assertRedirect('/account/export')->assertHeader('Cache-Control', 'no-store, private');
    $export = AccountExport::sole();
    expect($export->user_id)->toBe($this->owner->id)->and($export->status)->toBe(AccountExportStatus::Pending);
    Queue::assertPushed(GenerateAccountExport::class, fn (GenerateAccountExport $job): bool => $job->exportId === $export->id
        && $job instanceof ShouldBeEncrypted && $job->afterCommit);
    Queue::assertPushed(GenerateAccountExport::class, 1);
    Notification::assertNothingSent();
});

it('prevents requests for other users and enforces cooldown and pending-job deduplication', function (): void {
    $this->actingAs($this->owner);
    $other = User::factory()->create();
    expect(fn () => app(RequestAccountExport::class)->handle($other))->toThrow(AuthorizationException::class);
    expect(fn () => app(ListAccountExports::class)->handle($other))->toThrow(AuthorizationException::class);
    $this->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    $this->post('/account/export', ['confirm' => true])->assertRedirect();
    $this->post('/account/export', ['confirm' => true])->assertSessionHasErrors('confirm');
    $this->travel(61)->minutes();
    $this->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    $this->post('/account/export', ['confirm' => true])->assertSessionHasErrors('confirm');
    AccountExport::sole()->update(['status' => AccountExportStatus::Failed]);
    $this->post('/account/export', ['confirm' => true])->assertRedirect('/account/export');
    expect(AccountExport::count())->toBe(2);
});

it('lists only owned requests twelve per page with safe metadata and handles malformed page input', function (): void {
    accountExportFixture(User::factory()->create());
    for ($number = 0; $number < 13; $number++) {
        accountExportFixture($this->owner, AccountExportStatus::Failed);
    }
    $this->actingAs($this->owner)->withSession(['auth.password_confirmed_at' => now()->timestamp])
        ->get('/account/export')->assertOk()->assertViewHas('exports', fn ($exports): bool => $exports->total() === 13 && $exports->count() === 12)
        ->assertHeader('Cache-Control', 'no-store, private')->assertDontSee('account-exports/');
    $this->get('/account/export?page=2')->assertOk()->assertViewHas('exports', fn ($exports): bool => $exports->count() === 1);
    $this->get('/account/export?page[]=invalid')->assertRedirect('/account/export')->assertSessionHasErrors('page');
    $this->get('/account/export')->assertOk();
});

it('generates a private scoped JSON file with no credentials raw sessions or other users data', function (): void {
    config(['session.driver' => 'database', 'session.connection' => null, 'session.lifetime' => 120]);
    $other = User::factory()->create(['email' => 'not-in-export@example.test']);
    $owned = oauthClientFixture($this->owner, true);
    $owned->forceFill(['revoked' => true])->save();
    $foreignClient = oauthClientFixture($other);
    $foreignClient->forceFill(['name' => 'Foreign owned application'])->save();
    $morphImpostor = oauthClientFixture();
    $morphImpostor->forceFill(['owner_id' => $this->owner->id, 'owner_type' => 'not-the-user-model', 'name' => 'Foreign morph owner'])->save();
    foreach ([$this->owner, $other] as $user) {
        Consent::create(['user_id' => $user->id, 'client_id' => $owned->id, 'scopes' => ['openid'], 'granted_at' => now(), 'revoked_at' => now()]);
        AuditLog::create(['user_id' => $user->id, 'client_id' => $owned->id, 'event' => OAuthAuditEvent::ConsentRevoked]);
        DB::table('sessions')->insert(['id' => 'private-raw-session-'.$user->id, 'user_id' => $user->id,
            'payload' => 'private-session-payload', 'user_agent' => 'Windows Chrome/130', 'ip_address' => '192.0.2.'.$user->id, 'last_activity' => now()->timestamp]);
    }
    $export = accountExportFixture($this->owner);
    (new GenerateAccountExport($export->id))->handle(app(AccountExportWriter::class));
    $file = Storage::disk('local')->get($export->relativePath());
    $data = json_decode($file, true, 512, JSON_THROW_ON_ERROR);
    expect($data['profile']['id'])->toBe($this->owner->id)
        ->and($data['profile']['email'])->toBe($this->owner->email)
        ->and($data['owned_applications'])->toHaveCount(1)
        ->and($data['owned_applications'][0]['id'])->toBe($owned->id)
        ->and($data['owned_applications'][0]['deleted'])->toBeTrue()
        ->and($data['connected_apps'])->toHaveCount(1)->and($data['connected_apps'][0]['revoked_at'])->not->toBeNull()
        ->and($data['active_sessions'])->toHaveCount(1)->and($data['active_sessions'][0]['device'])->toBe('Chrome on Windows')
        ->and($data['audit_history'])->toHaveCount(1)
        ->and($file)->not->toContain($this->owner->password, $this->owner->remember_token, $owned->secret, $other->email,
            'private-raw-session', 'private-session-payload', 'Foreign owned application', 'Foreign morph owner', 'introspection_client_ids', 'two_factor_secret');
    expect($export->fresh()->status)->toBe(AccountExportStatus::Ready)
        ->and($export->fresh()->completed_at)->not->toBeNull()
        ->and($export->fresh()->expires_at->timestamp)->toBeGreaterThanOrEqual(now()->addDay()->subSecond()->timestamp)
        ->and(AuditLog::where('event', OAuthAuditEvent::AccountExported)->count())->toBe(1);
    Notification::assertSentToTimes($this->owner, AccountExportReady::class, 1);
    Notification::assertNotSentTo($other, AccountExportReady::class);
    Storage::disk('local')->assertMissing($export->relativePath().'.partial');
    (new GenerateAccountExport($export->id))->handle(app(AccountExportWriter::class));
    expect(AuditLog::where('event', OAuthAuditEvent::AccountExported)->count())->toBe(1);
    Notification::assertSentToTimes($this->owner, AccountExportReady::class, 1);
});

it('streams more than one batch and preserves historical audit events without enum casting', function (): void {
    $rows = [];
    for ($number = 0; $number < 251; $number++) {
        $rows[] = ['user_id' => $this->owner->id, 'event' => 'historical.event', 'created_at' => now()];
    }
    DB::table('audit_logs')->insert($rows);
    $export = accountExportFixture($this->owner);
    (new GenerateAccountExport($export->id))->handle(app(AccountExportWriter::class));
    $data = json_decode(Storage::disk('local')->get($export->relativePath()), true, 512, JSON_THROW_ON_ERROR);
    expect($data['audit_history'])->toHaveCount(251)->and($data['active_sessions'])->toBe([])
        ->and($data['notes'])->toContain('Session metadata is unavailable for this session store.');
});

it('protects download with owner verification password state and expiry independent of pruning', function (): void {
    $export = accountExportFixture($this->owner, AccountExportStatus::Ready);
    Storage::disk('local')->put($export->relativePath(), '{"safe":"export"}');
    $url = route('account.export.download', $export);
    $this->get($url)->assertRedirect('/login');
    $this->actingAs($this->owner)->get($url)->assertRedirect('/account/confirm-password');
    $this->withSession(['auth.password_confirmed_at' => now()->timestamp])->get($url)->assertOk()
        ->assertDownload('aether-account-export.json')->assertHeader('Content-Type', 'application/json')
        ->assertHeader('Cache-Control', 'no-store, private')->assertHeader('X-Content-Type-Options', 'nosniff')
        ->assertStreamedContent('{"safe":"export"}');
    $this->actingAs(User::factory()->create())->get($url)->assertForbidden();
    $this->actingAs(User::factory()->unverified()->create())->get($url)->assertRedirect('/email/verify');
    $this->actingAs($this->owner);
    $export->update(['expires_at' => now()->subSecond()]);
    $this->get($url)->assertNotFound();
    Storage::disk('local')->assertExists($export->relativePath());
    $this->get('/account/export')->assertOk()->assertSee('Expired.')->assertDontSee('Download JSON');
});

it('does not serve pending failed missing or malformed exports', function (): void {
    $this->actingAs($this->owner)->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    foreach ([AccountExportStatus::Pending, AccountExportStatus::Failed, AccountExportStatus::Ready] as $status) {
        $export = accountExportFixture($this->owner, $status);
        $this->get(route('account.export.download', $export))->assertNotFound();
    }
    $this->get('/account/export/not-a-uuid/download')->assertNotFound();
});

it('does not generate or notify after the owner becomes unverified or the request expires', function (bool $expired): void {
    $export = accountExportFixture($this->owner);
    if ($expired) {
        $export->update(['expires_at' => now()->subSecond()]);
        Storage::disk('local')->put($export->relativePath().'.partial', 'abandoned');
    } else {
        $this->owner->forceFill(['email_verified_at' => null])->save();
    }
    (new GenerateAccountExport($export->id))->handle(app(AccountExportWriter::class));
    expect($export->fresh()->status)->toBe($expired ? AccountExportStatus::Expired : AccountExportStatus::Failed);
    Notification::assertNothingSent();
    Storage::disk('local')->assertMissing($export->relativePath());
    Storage::disk('local')->assertMissing($export->relativePath().'.partial');
    expect(AuditLog::count())->toBe(0);
})->with([true, false]);

it('rolls back readiness and removes generated files if the success audit fails', function (): void {
    $export = accountExportFixture($this->owner);
    AuditLog::creating(fn () => throw new RuntimeException('Synthetic export audit failure'));
    try {
        expect(fn () => (new GenerateAccountExport($export->id))->handle(app(AccountExportWriter::class)))->toThrow(RuntimeException::class);
        expect($export->fresh()->status)->toBe(AccountExportStatus::Pending)->and(AuditLog::count())->toBe(0);
        Storage::disk('local')->assertMissing($export->relativePath());
        Storage::disk('local')->assertMissing($export->relativePath().'.partial');
        Notification::assertNothingSent();
    } finally {
        AuditLog::flushEventListeners();
    }
    (new GenerateAccountExport($export->id))->handle(app(AccountExportWriter::class));
    expect($export->fresh()->available())->toBeTrue();
});

it('marks exhausted pending jobs failed but does not delete a completed export', function (): void {
    foreach ([AccountExportStatus::Pending, AccountExportStatus::Ready] as $status) {
        $export = accountExportFixture($this->owner, $status);
        Storage::disk('local')->put($export->relativePath(), 'private-data');
        (new GenerateAccountExport($export->id))->failed(new RuntimeException('Synthetic job failure'));
        expect($export->fresh()->status)->toBe($status === AccountExportStatus::Pending ? AccountExportStatus::Failed : AccountExportStatus::Ready);
        expect(Storage::disk('local')->exists($export->relativePath()))->toBe($status === AccountExportStatus::Ready);
    }
});

it('prunes only expired generated artifacts and retains active exports and unrelated files', function (): void {
    $expired = accountExportFixture($this->owner, AccountExportStatus::Ready);
    $expired->update(['expires_at' => now()->subSecond()]);
    $active = accountExportFixture($this->owner, AccountExportStatus::Ready);
    foreach ([$expired->relativePath(), $expired->relativePath().'.partial', $active->relativePath(), 'other-private-file.txt'] as $path) {
        Storage::disk('local')->put($path, 'private-data');
    }
    $this->artisan('account-exports:prune')->expectsOutput('Expired account exports removed: 1')->assertSuccessful();
    Storage::disk('local')->assertMissing($expired->relativePath());
    Storage::disk('local')->assertMissing($expired->relativePath().'.partial');
    Storage::disk('local')->assertExists($active->relativePath());
    Storage::disk('local')->assertExists('other-private-file.txt');
    expect($expired->fresh()->status)->toBe(AccountExportStatus::Expired)->and(app(PruneAccountExports::class)->handle())->toBe(0);
});

it('suppresses stale ready emails and uses an encrypted queued notification with a protected account link', function (): void {
    Notification::swap(new ChannelManager(app()));
    $export = accountExportFixture($this->owner, AccountExportStatus::Ready);
    $notification = new AccountExportReady($export->id);
    expect($notification->shouldSend($this->owner, 'mail'))->toBeTrue()
        ->and($notification->shouldSend(User::factory()->create(), 'mail'))->toBeFalse()
        ->and($notification->toMail($this->owner)->actionUrl)->toBe(url('/account/export'));
    $this->owner->notify($notification);
    Queue::assertPushed(SendQueuedNotifications::class, fn (SendQueuedNotifications $job): bool => $job->notification instanceof AccountExportReady
        && $job->shouldBeEncrypted && $job->afterCommit);
    $export->update(['expires_at' => now()->subSecond()]);
    expect($notification->shouldSend($this->owner, 'mail'))->toBeFalse();
});

it('does not queue a generation job when the request transaction rolls back', function (): void {
    $this->actingAs($this->owner);
    Gate::policy(AccountExport::class, AccountExportPolicy::class);
    AccountExport::created(fn () => throw new RuntimeException('Synthetic request failure'));
    try {
        expect(fn () => app(RequestAccountExport::class)->handle($this->owner))->toThrow(RuntimeException::class);
        expect(AccountExport::count())->toBe(0);
        Queue::assertNothingPushed();
    } finally {
        AccountExport::flushEventListeners();
    }
});

it('processes encrypted generation and ready mail through the real database queue', function (): void {
    config(['queue.default' => 'database']);
    Queue::swap($this->realQueue);
    Notification::swap(new ChannelManager(app()));
    $this->actingAs($this->owner)->withSession(['auth.password_confirmed_at' => now()->timestamp])
        ->post('/account/export', ['confirm' => true])->assertRedirect('/account/export');
    $export = AccountExport::sole();
    expect(DB::table('jobs')->count())->toBe(1)
        ->and(DB::table('jobs')->sole()->payload)->not->toContain($export->id, $this->owner->email);
    $this->artisan('queue:work', ['connection' => 'database', '--once' => true, '--tries' => 1, '--timeout' => 0])->assertSuccessful();
    expect($export->fresh()->available())->toBeTrue()->and(DB::table('jobs')->count())->toBe(1);
    $this->artisan('queue:work', ['connection' => 'database', '--once' => true, '--tries' => 1, '--timeout' => 0])->assertSuccessful();
    expect(DB::table('failed_jobs')->count())->toBe(0)->and(DB::table('jobs')->count())->toBe(0);
    $mail = app('mailer')->getSymfonyTransport()->messages()->sole()->getOriginalMessage();
    expect($mail->getSubject())->toBe('Your Aether account export is ready')
        ->and($mail->getHtmlBody())->toContain('/account/export', 'confirm your password')
        ->not->toContain('account-exports/', $export->relativePath(), $this->owner->password);
});

it('does not let notification queue failure remove a committed ready file', function (): void {
    $export = accountExportFixture($this->owner);
    Notification::shouldReceive('send')->once()->andThrow(new RuntimeException('Synthetic notification failure'));
    expect(fn () => (new GenerateAccountExport($export->id))->handle(app(AccountExportWriter::class)))->toThrow(RuntimeException::class);
    expect($export->fresh()->available())->toBeTrue()
        ->and(AuditLog::where('event', OAuthAuditEvent::AccountExported)->count())->toBe(1);
    Storage::disk('local')->assertExists($export->relativePath());
    (new GenerateAccountExport($export->id))->failed(new RuntimeException('Synthetic final failure'));
    Storage::disk('local')->assertExists($export->relativePath());
    Notification::fake();
    $originalExpiry = $export->fresh()->expires_at->timestamp;
    (new GenerateAccountExport($export->id))->handle(app(AccountExportWriter::class));
    expect($export->fresh()->status)->toBe(AccountExportStatus::Ready)
        ->and($export->fresh()->expires_at->timestamp)->toBe($originalExpiry)
        ->and(AuditLog::where('event', OAuthAuditEvent::AccountExported)->count())->toBe(1);
    Notification::assertSentToTimes($this->owner, AccountExportReady::class, 1);
});

it('honors the exact expiry boundary without waiting for cleanup', function (): void {
    $this->freezeTime();
    $export = accountExportFixture($this->owner, AccountExportStatus::Ready);
    $export->update(['expires_at' => now()]);
    Storage::disk('local')->put($export->relativePath(), 'expired-data');
    $this->actingAs($this->owner)->withSession(['auth.password_confirmed_at' => now()->timestamp])
        ->get(route('account.export.download', $export))->assertNotFound();
    $this->get('/account/export')->assertSee('Expired.')->assertDontSee('Download JSON');
});
