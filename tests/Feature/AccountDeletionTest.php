<?php

use App\Actions\Account\RequestAccountDeletion;
use App\Actions\Developer\RegisterApplication;
use App\Enums\AccountExportStatus;
use App\Enums\OAuthAuditEvent;
use App\Jobs\FinalizeAccountDeletion;
use App\Jobs\GenerateAccountExport;
use App\Models\AccountExport;
use App\Models\AuditLog;
use App\Models\Consent;
use App\Models\User;
use App\Notifications\AccountDeletionRequested;
use App\Notifications\AccountExportReady;
use App\Services\AccountExportWriter;
use App\Services\RevokeAccountAccess;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use Laravel\Fortify\Actions\EnableTwoFactorAuthentication;
use Laravel\Passport\Passport;
use Symfony\Component\HttpKernel\Exception\HttpException;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config(['session.driver' => 'database', 'session.connection' => null]);
    Notification::fake();
    Queue::fake();
    Storage::fake('local');
    $this->owner = User::factory()->create();
});

function pendingDeletion(User $user): User
{
    $user->forceFill(['deletion_requested_at' => now(), 'deletion_due_at' => now()->addDays(14)])->save();

    return $user;
}

it('requires verified authentication recent password and explicit deletion confirmation', function (): void {
    $this->get('/account/deletion')->assertRedirect('/login');
    $this->post('/account/deletion', ['confirm' => true])->assertRedirect('/login');
    $this->actingAs(User::factory()->unverified()->create())->get('/account/deletion')->assertRedirect('/email/verify');
    $this->actingAs($this->owner)->get('/account/deletion')->assertRedirect('/account/confirm-password');
    $this->withSession(['auth.password_confirmed_at' => now()->timestamp])->get('/account/deletion')
        ->assertOk()->assertSee('14 days')->assertSee('Download your data before continuing')->assertHeader('Cache-Control', 'no-store, private');
    $this->post('/account/deletion')->assertSessionHasErrors('confirm');
    expect($this->owner->fresh()->accountAvailable())->toBeTrue();
    $this->post('/account/deletion', ['confirm' => true])->assertRedirect('/login');
    $this->assertGuest();
    $user = $this->owner->fresh();
    expect($user->deletion_due_at->timestamp - $user->deletion_requested_at->timestamp)->toBe(14 * 86400);
    expect(AuditLog::where('event', OAuthAuditEvent::AccountDeletionRequested)->count())->toBe(1);
    Notification::assertSentTo($user, AccountDeletionRequested::class, fn ($notification): bool => $notification instanceof ShouldBeEncrypted && $notification->afterCommit);
});

it('blocks administrator deletion and any non-revoked owned app while respecting morph ownership', function (): void {
    $this->owner->forceFill(['is_admin' => true])->save();
    $this->actingAs($this->owner)->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    $this->get('/account/deletion')->assertSee('Administrator accounts cannot');
    $this->post('/account/deletion', ['confirm' => true])->assertForbidden();
    $this->owner->forceFill(['is_admin' => false])->save();
    $client = oauthClientFixture($this->owner);
    $client->forceFill(['status' => 'suspended'])->save();
    $this->post('/account/deletion', ['confirm' => true])->assertSessionHasErrors('confirm');
    $client->forceFill(['revoked' => true])->save();
    $foreign = oauthClientFixture();
    $foreign->forceFill(['owner_id' => $this->owner->id, 'owner_type' => 'other-owner-type'])->save();
    $this->post('/account/deletion', ['confirm' => true])->assertRedirect('/login');
    expect($client->fresh()->revoked)->toBeTrue()->and($foreign->fresh()->revoked)->toBeFalse();
});

it('atomically revokes all owned credentials sessions approvals and reset links without affecting others', function (): void {
    $other = User::factory()->create();
    $client = oauthClientFixture();
    $code = oauthCode($this, $this->owner, $client);
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, $code))->assertOk()->json();
    $otherCode = oauthCode($this, $other, $client);
    $otherTokens = $this->postJson('/oauth/token', oauthExchange($client, $otherCode))->assertOk()->json();
    foreach ([$this->owner, $other] as $user) {
        DB::table('sessions')->insert(['id' => 'deletion-test-'.$user->id, 'user_id' => $user->id, 'payload' => '', 'last_activity' => now()->timestamp]);
        DB::table('password_reset_tokens')->insert(['email' => $user->email, 'token' => 'fixture', 'created_at' => now()]);
    }
    $remember = $this->owner->remember_token;
    $this->actingAs($this->owner)->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    $this->post('/account/deletion', ['confirm' => true])->assertRedirect('/login');
    expect(oauthBearerWorks($tokens['access_token']))->toBeFalse()->and(oauthBearerWorks($otherTokens['access_token']))->toBeTrue();
    expect(Passport::token()->newQuery()->where('user_id', $this->owner->id)->where('revoked', false)->exists())->toBeFalse();
    expect(Consent::where('user_id', $this->owner->id)->whereNull('revoked_at')->exists())->toBeFalse();
    expect(DB::table('sessions')->where('id', 'deletion-test-'.$this->owner->id)->exists())->toBeFalse();
    expect(DB::table('sessions')->where('id', 'deletion-test-'.$other->id)->exists())->toBeTrue();
    expect(DB::table('password_reset_tokens')->where('email', $this->owner->email)->exists())->toBeFalse();
    expect($this->owner->fresh()->remember_token)->not->toBe($remember);
    $this->postJson('/oauth/token', ['grant_type' => 'refresh_token', 'client_id' => $client->id, 'refresh_token' => $tokens['refresh_token']])->assertStatus(400);
});

it('rejects pending authorization code exchange and authorization even if revocation flags are stale', function (): void {
    $client = oauthClientFixture();
    $code = oauthCode($this, $this->owner, $client);
    pendingDeletion($this->owner);
    $this->postJson('/oauth/token', oauthExchange($client, $code))->assertStatus(400);
    expect($client->acceptsUser($this->owner->fresh()))->toBeFalse();
    $this->get(oauthAuthorizeUrl(oauthParameters($client)))->assertRedirect('/login');
});

it('restricts a completed password login to cancellation and requires an explicit cancellation', function (): void {
    pendingDeletion($this->owner);
    $this->post('/login', ['email' => $this->owner->email, 'password' => 'password'])->assertRedirect('/account/deletion/pending');
    $this->get('/account/deletion/pending')->assertOk()->assertSee('Cancel account deletion')->assertDontSee('Developer portal');
    $this->get('/account/profile')->assertRedirect('/account/deletion/pending');
    $this->get('/account/export')->assertRedirect('/account/deletion/pending');
    $this->post('/account/deletion/cancel')->assertSessionHasErrors('confirm');
    expect($this->owner->fresh()->deletion_requested_at)->not->toBeNull();
    $this->post('/account/deletion/cancel', ['confirm' => true])->assertRedirect('/login');
    $this->assertGuest();
    expect($this->owner->fresh()->accountAvailable())->toBeTrue();
    expect(AuditLog::where('event', OAuthAuditEvent::AccountDeletionCancelled)->count())->toBe(1);
});

it('requires the existing second factor before granting cancellation access', function (): void {
    app(EnableTwoFactorAuthentication::class)($this->owner);
    $this->owner->forceFill(['two_factor_confirmed_at' => now()])->save();
    $recovery = $this->owner->recoveryCodes()[0];
    pendingDeletion($this->owner);
    $this->post('/login', ['email' => $this->owner->email, 'password' => 'password'])->assertRedirect('/two-factor-challenge');
    $this->get('/account/deletion/pending')->assertRedirect('/login');
    $this->post('/two-factor-challenge', ['code' => 'invalid'])->assertSessionHasErrors('code');
    $this->post('/two-factor-challenge', ['recovery_code' => $recovery])->assertRedirect('/account/deletion/pending');
    expect($this->owner->fresh()->recoveryCodes())->not->toContain($recovery);
    $this->post('/account/deletion/cancel', ['confirm' => true])->assertRedirect('/login');
});

it('rejects stale existing sessions and expires cancellation proof after five minutes', function (): void {
    $this->actingAs($this->owner);
    pendingDeletion($this->owner);
    $this->post('/account/deletion/cancel', ['confirm' => true])->assertRedirect('/login');
    $this->assertGuest();
    $this->post('/login', ['email' => $this->owner->email, 'password' => 'password'])->assertRedirect('/account/deletion/pending');
    $this->travel(301)->seconds();
    $this->post('/account/deletion/cancel', ['confirm' => true])->assertRedirect('/login');
    expect($this->owner->fresh()->deletionCancellable())->toBeTrue();
});

it('refuses cancellation at the exact deadline even when the worker has not run', function (): void {
    pendingDeletion($this->owner);
    $this->post('/login', ['email' => $this->owner->email, 'password' => 'password'])->assertRedirect('/account/deletion/pending');
    $this->travelTo($this->owner->deletion_due_at);
    $this->post('/account/deletion/cancel', ['confirm' => true])->assertRedirect('/login');
    expect($this->owner->fresh()->anonymized_at)->toBeNull();
    $this->post('/login', ['email' => $this->owner->email, 'password' => 'password'])->assertForbidden();
});

it('blocks pending export downloads generation and ready notifications', function (): void {
    $export = AccountExport::create(['user_id' => $this->owner->id, 'status' => AccountExportStatus::Pending, 'expires_at' => now()->addDay()]);
    pendingDeletion($this->owner);
    (new GenerateAccountExport($export->id))->handle(app(AccountExportWriter::class));
    expect($export->fresh()->status)->toBe(AccountExportStatus::Failed);
    Storage::disk('local')->assertMissing($export->relativePath());
    expect((new AccountExportReady($export->id))->shouldSend($this->owner->fresh(), 'mail'))->toBeFalse();
    $this->actingAs($this->owner)->get('/account/export/'.$export->id.'/download')->assertRedirect('/login');
});

it('finalizes only after the deadline erases account data and is idempotent', function (): void {
    $other = User::factory()->create();
    $client = oauthClientFixture();
    $code = oauthCode($this, $this->owner, $client);
    $this->postJson('/oauth/token', oauthExchange($client, $code))->assertOk();
    $originalEmail = $this->owner->email;
    $this->owner->forceFill(['avatar_path' => 'avatars/deletion-test.png', 'is_developer' => true])->save();
    Storage::disk('local')->put('avatars/deletion-test.png', 'fixture');
    Storage::disk('local')->put('unrelated.txt', 'keep');
    $export = AccountExport::create(['user_id' => $this->owner->id, 'status' => AccountExportStatus::Ready, 'expires_at' => now()->addDay()]);
    Storage::disk('local')->put($export->relativePath(), 'private data');
    Storage::disk('local')->put($export->relativePath().'.partial', 'partial');
    pendingDeletion($this->owner);
    $job = new FinalizeAccountDeletion($this->owner->id);
    $job->handle(app(RevokeAccountAccess::class));
    expect($this->owner->fresh()->anonymized_at)->toBeNull();
    $this->travelTo($this->owner->deletion_due_at);
    $job->handle(app(RevokeAccountAccess::class));
    $job->handle(app(RevokeAccountAccess::class));
    $user = $this->owner->fresh();
    expect($user->name)->toBe('Deleted account')->and($user->email)->not->toBe($originalEmail)
        ->and($user->anonymized_at)->not->toBeNull()->and($user->avatar_path)->toBeNull()->and($user->two_factor_secret)->toBeNull()
        ->and($user->remember_token)->toBeNull()->and($user->is_developer)->toBeFalse()->and($user->accountAvailable())->toBeFalse();
    expect(Consent::where('user_id', $user->id)->count())->toBe(0);
    expect(AccountExport::where('user_id', $user->id)->count())->toBe(0);
    expect(Passport::token()->newQuery()->where('user_id', $user->id)->count())->toBe(0);
    expect(Passport::authCode()->newQuery()->where('user_id', $user->id)->count())->toBe(0);
    expect(AuditLog::where('event', OAuthAuditEvent::AccountDeleted)->count())->toBe(1);
    expect($other->fresh()->email)->toBe($other->email);
    Storage::disk('local')->assertMissing(['avatars/deletion-test.png', $export->relativePath(), $export->relativePath().'.partial']);
    Storage::disk('local')->assertExists('unrelated.txt');
});

it('does not finalize a cancelled request and schedules only due accounts in encrypted jobs', function (): void {
    pendingDeletion($this->owner);
    $due = pendingDeletion(User::factory()->create());
    $due->forceFill(['deletion_due_at' => now()->subSecond()])->save();
    $this->artisan('accounts:finalize-deletions')->assertSuccessful();
    Queue::assertPushed(FinalizeAccountDeletion::class, 1);
    Queue::assertPushed(FinalizeAccountDeletion::class, fn ($job): bool => $job->userId === $due->id && $job instanceof ShouldBeEncrypted);
    $this->owner->forceFill(['deletion_requested_at' => null, 'deletion_due_at' => null])->save();
    (new FinalizeAccountDeletion($this->owner->id))->handle(app(RevokeAccountAccess::class));
    expect($this->owner->fresh()->anonymized_at)->toBeNull();
});

it('rolls back deletion state and revocation when audit persistence fails', function (): void {
    $this->actingAs($this->owner);
    DB::table('sessions')->insert(['id' => 'rollback-deletion', 'user_id' => $this->owner->id, 'payload' => '', 'last_activity' => now()->timestamp]);
    AuditLog::creating(function (AuditLog $audit): void {
        if ($audit->event === OAuthAuditEvent::AccountDeletionRequested) {
            throw new RuntimeException('Simulated audit failure');
        }
    });
    try {
        expect(fn () => app(RequestAccountDeletion::class)->handle($this->owner))->toThrow(RuntimeException::class);
        expect($this->owner->fresh()->accountAvailable())->toBeTrue();
        expect(DB::table('sessions')->where('id', 'rollback-deletion')->exists())->toBeTrue();
        Notification::assertNotSentTo($this->owner, AccountDeletionRequested::class);
    } finally {
        AuditLog::flushEventListeners();
    }
});

it('rechecks stale account models before registering apps or requesting deletion', function (): void {
    $this->owner->forceFill(['is_developer' => true])->save();
    $this->actingAs($this->owner);
    $stale = $this->owner->fresh();
    pendingDeletion($this->owner);
    $this->actingAs($stale);
    expect(fn () => app(RequestAccountDeletion::class)->handle($stale))->toThrow(AuthorizationException::class);
    expect(fn () => app(RegisterApplication::class)->handle($stale, ['app_type' => 'machine', 'name' => 'Cannot create']))->toThrow(HttpException::class);
});

it('suppresses obsolete request emails after cancellation and keeps mail free of credentials', function (): void {
    pendingDeletion($this->owner);
    $notification = new AccountDeletionRequested($this->owner->deletion_due_at->toISOString());
    expect($notification->shouldSend($this->owner, 'mail'))->toBeTrue();
    $mail = $notification->toMail($this->owner)->render()->toHtml();
    expect($mail)->toContain('Your Aether access has been disabled')->not->toContain($this->owner->password);
    $this->owner->forceFill(['deletion_requested_at' => null, 'deletion_due_at' => null])->save();
    expect($notification->shouldSend($this->owner, 'mail'))->toBeFalse();
});

it('rejects a two-factor challenge started before deletion and an expired password challenge', function (): void {
    app(EnableTwoFactorAuthentication::class)($this->owner);
    $this->owner->forceFill(['two_factor_confirmed_at' => now()])->save();
    $recovery = $this->owner->recoveryCodes()[0];
    $this->post('/login', ['email' => $this->owner->email, 'password' => 'password'])->assertRedirect('/two-factor-challenge');
    pendingDeletion($this->owner);
    $this->post('/two-factor-challenge', ['recovery_code' => $recovery])->assertForbidden();
    $this->post('/login', ['email' => $this->owner->email, 'password' => 'password'])->assertRedirect('/two-factor-challenge');
    $this->travel(301)->seconds();
    $this->post('/two-factor-challenge', ['recovery_code' => $recovery])->assertForbidden();
    expect($this->owner->fresh()->recoveryCodes())->toContain($recovery);
});

it('fails closed for unsupported session stores without recording deletion', function (): void {
    $this->actingAs($this->owner);
    config(['session.driver' => 'array']);
    expect(fn () => app(RequestAccountDeletion::class)->handle($this->owner))->toThrow(HttpException::class);
    expect($this->owner->fresh()->accountAvailable())->toBeTrue();
    Notification::assertNothingSent();
});

it('keeps finalization retryable if storage cleanup fails', function (): void {
    pendingDeletion($this->owner);
    $this->travelTo($this->owner->deletion_due_at);
    $export = AccountExport::create(['user_id' => $this->owner->id, 'status' => AccountExportStatus::Ready, 'expires_at' => now()->addDay()]);
    $disk = Storage::disk('local');
    $disk->put($export->relativePath(), 'private');
    $failingDisk = Mockery::mock($disk)->makePartial();
    $failingDisk->shouldReceive('delete')->once()->andReturn(false);
    Storage::shouldReceive('disk')->with('local')->once()->andReturn($failingDisk);
    expect(fn () => (new FinalizeAccountDeletion($this->owner->id))->handle(app(RevokeAccountAccess::class)))->toThrow(RuntimeException::class);
    expect($this->owner->fresh()->anonymized_at)->toBeNull()->and($export->fresh())->not->toBeNull();
    expect(AuditLog::where('event', OAuthAuditEvent::AccountDeleted)->exists())->toBeFalse();
});

it('retains deleted client records and blocks finalization if a live app appears during the grace period', function (): void {
    $retained = oauthClientFixture($this->owner);
    $retained->forceFill(['revoked' => true])->save();
    pendingDeletion($this->owner);
    $this->travelTo($this->owner->deletion_due_at);
    $active = oauthClientFixture($this->owner);
    $job = new FinalizeAccountDeletion($this->owner->id);
    expect(fn () => $job->handle(app(RevokeAccountAccess::class)))->toThrow(RuntimeException::class);
    expect($this->owner->fresh()->anonymized_at)->toBeNull();
    $active->forceFill(['revoked' => true])->save();
    $job->handle(app(RevokeAccountAccess::class));
    expect($retained->fresh())->not->toBeNull()->and($retained->fresh()->owner_id)->toBe($this->owner->id);
});
