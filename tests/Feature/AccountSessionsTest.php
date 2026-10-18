<?php

use App\Actions\Account\ListSessions;
use App\Actions\Account\RevokeSessions;
use App\Enums\OAuthAuditEvent;
use App\Models\AuditLog;
use App\Models\User;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Auth\SessionGuard;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Session\DatabaseSessionHandler;
use Illuminate\Session\Store;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config(['session.driver' => 'database', 'session.connection' => null, 'session.table' => 'sessions', 'session.lifetime' => 120]);
    $this->owner = User::factory()->create(['remember_token' => 'disposable-remember-token']);
    $this->actingAs($this->owner)->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    $this->currentSessionId = session()->getId();
    session()->save();
    $this->withCookie(config('session.cookie'), $this->currentSessionId);
});

function accountSessionFixture(User $user, string $identifier, array $overrides = []): void
{
    DB::table('sessions')->insert(array_replace([
        'id' => $identifier, 'user_id' => $user->id, 'ip_address' => '192.0.2.14',
        'user_agent' => 'Mozilla/5.0 (Windows NT 10.0) Chrome/130.0',
        'payload' => base64_encode('private-session-payload'), 'last_activity' => now()->timestamp,
    ], $overrides));
}

it('lists only recent owned sessions with safe metadata and protected row references', function (): void {
    accountSessionFixture($this->owner, 'other-private-session');
    accountSessionFixture($this->owner, 'expired-private-session', ['last_activity' => now()->subMinutes(121)->timestamp]);
    accountSessionFixture(User::factory()->create(), 'foreign-private-session', ['ip_address' => '192.0.2.99']);
    $this->get(route('account.sessions.index'))->assertOk()->assertHeader('Cache-Control', 'no-store, private')
        ->assertSee('Chrome on Windows')->assertSee('192.0.2.14')->assertSee('UTC')
        ->assertSee('This session')
        ->assertDontSee('192.0.2.99')->assertDontSee('private-session-payload')
        ->assertDontSee('other-private-session')->assertDontSee('expired-private-session')->assertDontSee('foreign-private-session');
    $sessions = app(ListSessions::class)->handle($this->owner, $this->currentSessionId);
    expect($sessions->getCollection()->pluck('id')->all())->toContain('other-private-session')
        ->not->toContain('foreign-private-session', 'expired-private-session');
});

it('paginates twelve sessions and rejects malformed page input without redirect loops', function (): void {
    foreach (range(1, 14) as $number) {
        accountSessionFixture($this->owner, 'private-session-'.$number);
    }
    $this->get(route('account.sessions.index'))->assertOk()->assertSee('Page 1 of 2');
    $this->get(route('account.sessions.index', ['page' => ['bad']]))->assertRedirect(route('account.sessions.index'))->assertSessionHasErrors('page');
});

it('requires verified login recent password and explicit confirmation', function (): void {
    $this->app['auth']->forgetGuards();
    $this->get(route('account.sessions.index'))->assertRedirect('/login');
    $this->actingAs(User::factory()->unverified()->create())->get(route('account.sessions.index'))->assertRedirect('/email/verify');
    $this->actingAs($this->owner)->withSession(['auth.password_confirmed_at' => now()->subSeconds(301)->timestamp]);
    session()->save();
    $this->post(route('account.sessions.revoke-others'), ['confirm' => true])->assertRedirect(route('password.confirm'));
    $this->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    session()->save();
    $this->post(route('account.sessions.revoke-others'))->assertSessionHasErrors('confirm');
    expect(AuditLog::count())->toBe(0);
});

it('revokes exactly one owned session while preserving current foreign and other active sessions', function (): void {
    accountSessionFixture($this->owner, 'selected-session');
    accountSessionFixture($this->owner, 'kept-session');
    $foreign = User::factory()->create();
    accountSessionFixture($foreign, 'foreign-session');
    $before = $this->owner->remember_token;
    $this->post(route('account.sessions.revoke'), ['confirm' => true, 'session_reference' => Crypt::encryptString('selected-session')])
        ->assertRedirect(route('account.sessions.index'))->assertHeader('Cache-Control', 'no-store, private');
    expect(DB::table('sessions')->where('id', 'selected-session')->exists())->toBeFalse()
        ->and(DB::table('sessions')->where('id', 'kept-session')->exists())->toBeTrue()
        ->and(DB::table('sessions')->where('id', 'foreign-session')->exists())->toBeTrue()
        ->and($this->owner->fresh()->remember_token)->not->toBe($before);
    $this->assertAuthenticatedAs($this->owner);
    $audit = AuditLog::sole();
    expect($audit->event)->toBe(OAuthAuditEvent::SessionRevoked)->and($audit->user_id)->toBe($this->owner->id)->and($audit->client_id)->toBeNull();
});

it('revokes all other owned sessions including expired rows and keeps the current session', function (): void {
    accountSessionFixture($this->owner, 'other-session');
    accountSessionFixture($this->owner, 'old-session', ['last_activity' => now()->subDay()->timestamp]);
    accountSessionFixture(User::factory()->create(), 'foreign-session');
    $this->post(route('account.sessions.revoke-others'), ['confirm' => true])->assertRedirect(route('account.sessions.index'));
    expect(DB::table('sessions')->where('user_id', $this->owner->id)->where('id', '!=', $this->currentSessionId)->count())->toBe(0)
        ->and(DB::table('sessions')->where('id', 'foreign-session')->exists())->toBeTrue();
    $this->assertAuthenticatedAs($this->owner);
});

it('refuses foreign current forged and already removed references without rotating remember credentials', function (): void {
    accountSessionFixture(User::factory()->create(), 'foreign-session');
    foreach (['foreign-session', $this->currentSessionId, 'missing-session'] as $target) {
        expect(fn () => app(RevokeSessions::class)->handle($this->owner, $this->currentSessionId, Crypt::encryptString($target)))
            ->toThrow(ValidationException::class);
    }
    expect(fn () => app(RevokeSessions::class)->handle($this->owner, $this->currentSessionId, 'forged-reference'))->toThrow(ValidationException::class);
    expect(AuditLog::count())->toBe(0)->and($this->owner->fresh()->remember_token)->toBe('disposable-remember-token');
});

it('checks account ownership in both actions and refuses unsupported session stores safely', function (): void {
    $foreign = User::factory()->create();
    expect(fn () => app(ListSessions::class)->handle($foreign, $this->currentSessionId))->toThrow(AuthorizationException::class);
    expect(fn () => app(RevokeSessions::class)->handle($foreign, $this->currentSessionId, null))->toThrow(AuthorizationException::class);
    config(['session.driver' => 'array']);
    $this->withSession(['auth.password_confirmed_at' => now()->timestamp])->get(route('account.sessions.index'))
        ->assertStatus(503)->assertDontSee('private-session-payload');
});

it('rolls back session deletion and remember rotation when auditing fails', function (): void {
    accountSessionFixture($this->owner, 'selected-session');
    AuditLog::creating(function (AuditLog $audit): void {
        if ($audit->event === OAuthAuditEvent::SessionRevoked) {
            throw new RuntimeException('Synthetic audit failure');
        }
    });
    try {
        expect(fn () => app(RevokeSessions::class)->handle($this->owner, $this->currentSessionId, Crypt::encryptString('selected-session')))
            ->toThrow(RuntimeException::class);
        expect(DB::table('sessions')->where('id', 'selected-session')->exists())->toBeTrue()
            ->and($this->owner->fresh()->remember_token)->toBe('disposable-remember-token');
    } finally {
        AuditLog::flushEventListeners();
    }
});

it('does not resurrect a deleted session when an already loaded database handler writes its response', function (): void {
    accountSessionFixture($this->owner, 'in-flight-session');
    $handler = new DatabaseSessionHandler(DB::connection(), 'sessions', 120, app());
    $handler->read('in-flight-session');
    app(RevokeSessions::class)->handle($this->owner, $this->currentSessionId, Crypt::encryptString('in-flight-session'));
    $handler->write('in-flight-session', 'stale-payload');
    expect(DB::table('sessions')->where('id', 'in-flight-session')->exists())->toBeFalse()
        ->and((new DatabaseSessionHandler(DB::connection(), 'sessions', 120, app()))->read('in-flight-session'))->toBe('');
});

it('rejects a revoked database session and its old remember cookie through the real session guard', function (): void {
    accountSessionFixture($this->owner, 'remembered-other-session');
    $oldRememberToken = $this->owner->remember_token;
    app(RevokeSessions::class)->handle($this->owner, $this->currentSessionId, Crypt::encryptString('remembered-other-session'));
    $handler = new DatabaseSessionHandler(DB::connection(), 'sessions', 120, app());
    $store = new Store('isolated-revoked-session', $handler);
    $store->setId('remembered-other-session');
    $store->start();
    $provider = new EloquentUserProvider(app('hash'), User::class);
    $guard = new SessionGuard('web', $provider, $store);
    $request = Request::create('/', 'GET', [], [
        $guard->getRecallerName() => $this->owner->id.'|'.$oldRememberToken.'|'.$this->owner->password,
    ]);
    $guard->setRequest($request);
    expect($guard->user())->toBeNull()->and($guard->viaRemember())->toBeFalse();
});
