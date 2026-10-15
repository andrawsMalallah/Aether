<?php

use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Gate;

uses(RefreshDatabase::class);

it('requires login and verified email for developer pages and activation', function (): void {
    $this->get('/account/developer')->assertRedirect('/login');
    $this->post('/account/developer/enable')->assertRedirect('/login');
    $this->get('/developer/apps')->assertRedirect('/login');
    $user = User::factory()->unverified()->create();
    $this->actingAs($user)->get('/account/developer')->assertRedirect('/email/verify');
    $this->post('/account/developer/enable')->assertRedirect('/email/verify');
    $this->get('/developer/apps')->assertRedirect('/email/verify');
    expect($user->fresh()->is_developer)->toBeFalse();
});

it('enables only the authenticated user and is safe to repeat', function (): void {
    $user = User::factory()->create();
    $other = User::factory()->create();
    $this->actingAs($user)->get('/account/developer')->assertOk()->assertSee('Become a developer');
    $this->post('/account/developer/enable', ['user_id' => $other->id, 'is_developer' => false, 'is_admin' => true])
        ->assertRedirect('/developer/apps')->assertSessionHas('status', 'Developer access is ready.');
    expect($user->fresh()->is_developer)->toBeTrue()->and($other->fresh()->is_developer)->toBeFalse()
        ->and($user->isFillable('is_developer'))->toBeFalse()
        ->and(Gate::forUser($user)->allows('enableDeveloper', $other))->toBeFalse();
    $this->post('/account/developer/enable')->assertRedirect('/developer/apps');
    $this->get('/account/developer')->assertRedirect('/developer/apps');
    $this->get('/developer/apps')->assertOk()->assertSee('No applications yet');
});

it('blocks the application list until developer access is enabled', function (): void {
    $this->actingAs(User::factory()->create())->get('/developer/apps')->assertForbidden();
});

it('lists only owned applications with escaped names and no credentials', function (): void {
    $user = User::factory()->create(['is_developer' => true]);
    $other = User::factory()->create(['is_developer' => true]);
    $own = oauthClientFixture($user, true);
    $own->forceFill(['name' => '<script>alert(1)</script>'])->save();
    oauthClientFixture($other)->forceFill(['name' => 'Other private application'])->save();
    oauthClientFixture()->forceFill(['name' => 'Unowned provider application'])->save();
    oauthClientFixture($user)->forceFill(['name' => 'Different owner type application', 'owner_type' => 'DifferentOwner'])->save();
    $response = $this->actingAs($user)->get('/developer/apps')->assertOk()
        ->assertSee('&lt;script&gt;alert(1)&lt;/script&gt;', false)->assertDontSee('<script>alert(1)</script>', false)
        ->assertSee('Web application')->assertSee('Live')
        ->assertDontSee('Other private application')->assertDontSee('Unowned provider application')
        ->assertDontSee('Different owner type application')
        ->assertDontSee($own->plainSecret)->assertDontSee($own->secret)->assertSee(route('developer.apps.show', $own));
    expect($response->viewData('applications')->total())->toBe(1);
});

it('paginates owned applications and hides permanently revoked records', function (): void {
    $user = User::factory()->create(['is_developer' => true]);
    for ($applicationNumber = 1; $applicationNumber <= 13; $applicationNumber++) {
        oauthClientFixture($user)->forceFill(['name' => 'Owned app '.$applicationNumber])->save();
    }
    oauthClientFixture($user)->forceFill(['name' => 'Deleted app marker', 'revoked' => true])->save();
    $first = $this->actingAs($user)->get('/developer/apps')->assertOk()->assertSee('Next')->assertDontSee('Deleted app marker');
    expect($first->viewData('applications')->count())->toBe(12)
        ->and($first->viewData('applications')->total())->toBe(13);
    $second = $this->get('/developer/apps?page=2')->assertOk()->assertSee('Previous');
    expect($second->viewData('applications')->count())->toBe(1);
});

it('does not enable developer access through profile updates', function (): void {
    $user = User::factory()->create();
    $this->actingAs($user)->put('/account/profile', ['name' => 'Updated name', 'is_developer' => true])->assertRedirect();
    expect($user->fresh()->is_developer)->toBeFalse();
});
