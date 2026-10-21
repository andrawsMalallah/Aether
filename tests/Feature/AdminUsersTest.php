<?php

use App\Actions\Admin\ListUsers;
use App\Http\Resources\AdminUserResource;
use App\Models\User;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Gate;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    $this->admin = User::factory()->create(['is_admin' => true, 'two_factor_secret' => Crypt::encryptString('user-test-only'), 'two_factor_confirmed_at' => now()]);
});

it('requires verified admin and confirmed two factor on both pages', function (): void {
    foreach (['/admin/users', '/admin/users/'.$this->admin->id] as $url) {
        auth()->forgetGuards();
        $this->get($url)->assertRedirect('/login');
        $this->actingAs(User::factory()->create(['is_developer' => true]))->get($url)->assertForbidden();
        $this->admin->forceFill(['email_verified_at' => null])->save();
        $this->actingAs($this->admin)->get($url)->assertRedirect('/email/verify');
        $this->admin->forceFill(['email_verified_at' => now(), 'two_factor_confirmed_at' => null])->save();
        $this->get($url)->assertRedirect(route('account.security'));
        $this->admin->forceFill(['two_factor_confirmed_at' => now()])->save();
        $this->get($url)->assertOk()->assertHeader('Cache-Control', 'no-store, private');
        $this->post($url)->assertStatus(405);
        $this->delete($url)->assertStatus(405);
    }
});

it('combines literal name or email search with overlapping roles and verification', function (): void {
    $target = User::factory()->create(['name' => 'Literal%_! account', 'email' => 'matching@example.test', 'is_admin' => true, 'is_developer' => true]);
    User::factory()->create(['name' => 'LiteralXXX account', 'is_developer' => true]);
    User::factory()->unverified()->create(['name' => 'Literal%_! unverified', 'is_developer' => true]);
    $this->actingAs($this->admin);
    foreach (['admin', 'developer'] as $role) {
        $this->get('/admin/users?'.http_build_query(['search' => '%_!', 'role' => $role, 'verification' => 'verified']))
            ->assertOk()->assertViewHas('users', fn ($users): bool => $users->total() === 1 && $users->first()['id'] === $target->id);
    }
    $this->get('/admin/users?search=MATCHING%40EXAMPLE')->assertViewHas('users', fn ($users): bool => $users->total() === 1);
    $this->get('/admin/users?role=user')->assertViewHas('users', fn ($users): bool => $users->total() === 0);
    $this->get('/admin/users?verification=unverified')->assertViewHas('users', fn ($users): bool => $users->total() === 1);
});

it('paginates with preserved filters and selects safe list fields', function (): void {
    User::factory()->count(13)->create(['is_developer' => true]);
    $this->actingAs($this->admin)->get('/admin/users?role=developer')->assertOk()
        ->assertViewHas('users', function ($users): bool {
            parse_str(parse_url($users->nextPageUrl(), PHP_URL_QUERY), $query);

            return $users->total() === 13 && $users->count() === 12 && $query === ['role' => 'developer', 'page' => '2'];
        });
    $record = app(ListUsers::class)->handle()->first();
    expect($record->getAttributes())->not->toHaveKeys(['password', 'two_factor_secret', 'two_factor_recovery_codes', 'remember_token']);
});

it('escapes identity and app text and exposes only safe detail metadata', function (): void {
    $target = User::factory()->create(['name' => '<script>identity</script>', 'two_factor_secret' => Crypt::encryptString('private-marker'), 'two_factor_confirmed_at' => now()]);
    $client = oauthClientFixture($target, true);
    $client->forceFill(['name' => '<script>owned</script>'])->save();
    $other = oauthClientFixture(User::factory()->create(), true);
    $other->forceFill(['name' => 'unrelated-app-marker'])->save();
    $this->actingAs($this->admin)->get('/admin/users/'.$target->id)->assertOk()
        ->assertSee('&lt;script&gt;identity&lt;/script&gt;', false)->assertSee('&lt;script&gt;owned&lt;/script&gt;', false)
        ->assertDontSee('<script>identity</script>', false)->assertDontSee('unrelated-app-marker')
        ->assertSee('Enabled and confirmed')->assertSee(route('admin.apps.show', $client))
        ->assertSee(route('admin.audit.index', ['actor' => $target->id]), false)
        ->assertDontSee($target->password)->assertDontSee($target->two_factor_secret)->assertDontSee('private-marker');
    expect(array_keys((new AdminUserResource($target))->resolve()))->toBe(['id', 'name', 'email', 'verified', 'roles', 'joined_at']);
    expect(Gate::forUser($this->admin)->allows('update', $target))->toBeFalse();
});

it('paginates apps and respects polymorphic ownership', function (): void {
    $target = User::factory()->create();
    foreach (range(1, 13) as $index) {
        oauthClientFixture($target, true);
    }
    $foreign = oauthClientFixture($target, true);
    $foreign->forceFill(['owner_type' => 'different-owner-type'])->save();
    $this->actingAs($this->admin)->get('/admin/users/'.$target->id)->assertOk()
        ->assertViewHas('applications', fn ($applications): bool => $applications->total() === 13 && $applications->count() === 12);
    $this->get('/admin/users/'.$target->id.'?page=2')->assertViewHas('applications', fn ($applications): bool => $applications->count() === 1);
    $this->get('/admin/users/99999999')->assertNotFound();
});

it('rejects malformed query filters safely', function (array $filters): void {
    $this->actingAs($this->admin)->get('/admin/users?'.http_build_query($filters))->assertRedirect(route('admin.users.index'))->assertSessionHasErrors();
})->with([
    [['search' => ['bad']]], [['role' => ['admin']]], [['role' => 'owner']],
    [['verification' => ['verified']]], [['verification' => 'yes']], [['page' => 0]], [['page' => ['1']]],
]);

it('enforces policies when actions are called directly', function (): void {
    $user = User::factory()->create();
    $this->actingAs($user);
    expect(Gate::allows('administer', $this->admin))->toBeFalse();
    app(ListUsers::class)->handle();
})->throws(AuthorizationException::class);
