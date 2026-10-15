<?php

use App\Actions\Admin\ListAuditLogs;
use App\Enums\OAuthAuditEvent;
use App\Http\Resources\AdminAuditLogResource;
use App\Models\AuditLog;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    $this->admin = User::factory()->create(['is_admin' => true, 'two_factor_secret' => Crypt::encryptString('audit-test-only'), 'two_factor_confirmed_at' => now()]);
});

it('requires verified administrator and confirmed two factor and exposes no audit writes', function (): void {
    $this->get('/admin/audit')->assertRedirect('/login');
    $this->actingAs(User::factory()->create(['is_developer' => true]))->get('/admin/audit')->assertForbidden();
    $this->admin->forceFill(['email_verified_at' => null])->save();
    $this->actingAs($this->admin)->get('/admin/audit')->assertRedirect('/email/verify');
    $this->admin->forceFill(['email_verified_at' => now(), 'two_factor_confirmed_at' => null])->save();
    $this->actingAs($this->admin)->get('/admin/audit')->assertRedirect(route('account.security'));
    $this->admin->forceFill(['two_factor_confirmed_at' => now()])->save();
    $this->actingAs($this->admin)->get('/admin/audit')->assertOk()->assertHeader('Cache-Control', 'no-store, private');
    $this->post('/admin/audit')->assertStatus(405);
    $this->delete('/admin/audit')->assertStatus(405);
});

it('shows safe escaped event metadata and preserves unavailable or absent record references', function (): void {
    $actor = User::factory()->create(['name' => '<script>actor</script>']);
    $client = oauthClientFixture($actor, true);
    $client->forceFill(['name' => '<script>client</script>'])->save();
    AuditLog::create(['user_id' => $actor->id, 'client_id' => $client->id, 'event' => OAuthAuditEvent::ClientSuspended]);
    AuditLog::create(['user_id' => 99999, 'client_id' => (string) Str::uuid(), 'event' => OAuthAuditEvent::ClientRestored]);
    AuditLog::create(['event' => OAuthAuditEvent::CodeReplayed]);
    DB::table('audit_logs')->insert(['event' => 'historical.event', 'created_at' => now()]);
    $this->actingAs($this->admin)->get('/admin/audit')->assertOk()->assertSee('client.suspended')->assertSee('UTC')
        ->assertSee('&lt;script&gt;actor&lt;/script&gt;', false)->assertSee('&lt;script&gt;client&lt;/script&gt;', false)
        ->assertDontSee('<script>actor</script>', false)->assertDontSee('<script>client</script>', false)
        ->assertSee('Unavailable user')->assertSee('99999')->assertSee('Unavailable application')
        ->assertSee('No user recorded')->assertSee('No application recorded')->assertSee('historical.event')
        ->assertDontSee($actor->password)->assertDontSee($client->secret)->assertDontSee($client->plainSecret);
    expect(AuditLog::count())->toBe(4);
});

it('combines exact action app actor and inclusive UTC dates without leaking adjacent events', function (): void {
    $actor = User::factory()->create();
    $client = oauthClientFixture($actor, true);
    foreach (['2026-10-14 23:59:59', '2026-10-15 00:00:00', '2026-10-15 23:59:59', '2026-10-16 00:00:00'] as $time) {
        $log = new AuditLog(['user_id' => $actor->id, 'client_id' => $client->id, 'event' => OAuthAuditEvent::ClientSuspended]);
        $log->created_at = $time;
        $log->save();
    }
    AuditLog::create(['user_id' => $actor->id, 'client_id' => $client->id, 'event' => OAuthAuditEvent::ClientRestored]);
    $filters = ['event' => 'client.suspended', 'client_id' => $client->id, 'actor' => $actor->email, 'from' => '2026-10-15', 'to' => '2026-10-15'];
    $this->actingAs($this->admin)->get('/admin/audit?'.http_build_query($filters))->assertOk()
        ->assertViewHas('logs', fn ($logs): bool => $logs->total() === 2 && $logs->first()['time'] === '2026-10-15 23:59:59');
    $filters['actor'] = (string) $actor->id;
    $this->get('/admin/audit?'.http_build_query($filters))->assertOk()->assertViewHas('logs', fn ($logs): bool => $logs->total() === 2);
    $this->get('/admin/audit?'.http_build_query(['to' => '2026-10-14']))->assertOk()->assertViewHas('logs', fn ($logs): bool => $logs->total() === 1);
    $this->get('/admin/audit?actor=nobody%40example.test')->assertOk()->assertSee('No events match your filters.');
});

it('paginates newest first with a stable id tie break and preserves only validated filters', function (): void {
    for ($number = 0; $number < 13; $number++) {
        $log = new AuditLog(['user_id' => $this->admin->id, 'event' => OAuthAuditEvent::ClientSuspended]);
        $log->created_at = '2026-10-15 10:00:00';
        $log->save();
    }
    $this->actingAs($this->admin)->get('/admin/audit?event=client.suspended&actor='.$this->admin->id.'&unrelated=discard')
        ->assertOk()->assertViewHas('logs', function ($logs): bool {
            parse_str(parse_url($logs->nextPageUrl(), PHP_URL_QUERY), $query);

            return $logs->total() === 13 && $logs->count() === 12 && $logs->first()['id'] === 13
                && $query === ['event' => 'client.suspended', 'actor' => (string) $this->admin->id, 'page' => '2'];
        });
    $this->get('/admin/audit?event=client.suspended&page=2')->assertOk()->assertViewHas('logs', fn ($logs): bool => $logs->count() === 1 && $logs->first()['id'] === 1);
});

it('eager loads only display fields with a bounded number of queries', function (): void {
    $client = oauthClientFixture($this->admin, true);
    for ($number = 0; $number < 12; $number++) {
        AuditLog::create(['user_id' => $this->admin->id, 'client_id' => $client->id, 'event' => OAuthAuditEvent::ClientUpdated]);
    }
    $this->actingAs($this->admin);
    DB::enableQueryLog();
    DB::flushQueryLog();
    $logs = app(ListAuditLogs::class)->handle();
    foreach ($logs as $log) {
        expect(array_keys($log->actor->getAttributes()))->toBe(['id', 'name', 'email'])
            ->and(array_keys($log->client->getAttributes()))->toBe(['id', 'name']);
        (new AdminAuditLogResource($log))->resolve();
    }
    expect(count(DB::getQueryLog()))->toBe(4);
    DB::disableQueryLog();
});

it('rejects invalid audit filters without scalar input errors or redirect loops', function (array $filters, string $field): void {
    $this->actingAs($this->admin)->get('/admin/audit?'.http_build_query($filters))->assertRedirect(route('admin.audit.index'))->assertSessionHasErrors($field);
    $this->get('/admin/audit')->assertOk()->assertSee('Audit log');
})->with([
    'event array' => [['event' => ['client.suspended']], 'event'],
    'unknown event' => [['event' => 'not-recorded'], 'event'],
    'client array' => [['client_id' => ['bad']], 'client_id'],
    'invalid client' => [['client_id' => 'bad'], 'client_id'],
    'actor array' => [['actor' => ['bad']], 'actor'],
    'long actor' => [['actor' => str_repeat('a', 256)], 'actor'],
    'date array' => [['from' => ['bad']], 'from'],
    'invalid date' => [['from' => '2026-02-30'], 'from'],
    'reverse range' => [['from' => '2026-10-16', 'to' => '2026-10-15'], 'to'],
    'page array' => [['page' => [2]], 'page'],
]);
