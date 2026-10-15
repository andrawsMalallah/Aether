<?php

use App\Actions\Admin\ApproveMachineApplication;
use App\Actions\Admin\ListMachineResources;
use App\Enums\OAuthAppType;
use App\Enums\OAuthAuditEvent;
use App\Enums\OAuthClientStatus;
use App\Models\AuditLog;
use App\Models\OAuthClient;
use App\Models\User;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;

uses(RefreshDatabase::class);

function approvalMachineFixture(User $owner): OAuthClient
{
    $client = app(ClientRepository::class)->createClientCredentialsGrantClient('Pending service');
    $client->owner()->associate($owner);
    $client->forceFill(['app_type' => OAuthAppType::Machine, 'status' => OAuthClientStatus::Testing, 'allowed_scopes' => []])->save();

    return $client;
}

function approvalResourceFixture(string $name = 'Statistics API'): OAuthClient
{
    $resource = oauthClientFixture(confidential: true);
    $resource->forceFill(['name' => $name, 'introspection_client_ids' => []])->save();

    return $resource;
}

beforeEach(function (): void {
    $this->owner = User::factory()->create(['is_developer' => true]);
    $this->admin = User::factory()->create(['is_admin' => true, 'two_factor_secret' => Crypt::encryptString('approval-test-only'), 'two_factor_confirmed_at' => now()]);
    $this->machine = approvalMachineFixture($this->owner);
    $this->resource = approvalResourceFixture();
    $this->approval = ['scopes' => ['stats:read'], 'resources' => [$this->resource->id], 'confirm' => true];
});

it('requires verified confirmed two factor admin recent password and explicit confirmation', function (): void {
    $url = route('admin.apps.machine.approve.confirm', $this->machine);
    $post = route('admin.apps.machine.approve', $this->machine);
    $this->get($url)->assertRedirect('/login');
    $this->post($post, $this->approval)->assertRedirect('/login');
    $this->actingAs($this->owner)->get($url)->assertForbidden();
    $this->post($post, $this->approval)->assertForbidden();
    $this->admin->forceFill(['email_verified_at' => null])->save();
    $this->actingAs($this->admin)->get($url)->assertRedirect('/email/verify');
    $this->admin->forceFill(['email_verified_at' => now(), 'two_factor_confirmed_at' => null])->save();
    $this->get($url)->assertRedirect(route('account.security'));
    $this->post($post, $this->approval)->assertRedirect(route('account.security'));
    $this->admin->forceFill(['two_factor_confirmed_at' => now()])->save();
    $this->get($url)->assertRedirect(route('password.confirm'));
    $this->post($post, $this->approval)->assertRedirect(route('password.confirm'));
    $this->withSession(['auth.password_confirmed_at' => now()->subSeconds(301)->timestamp])->post($post, $this->approval)->assertRedirect(route('password.confirm'));
    $this->withSession(['auth.password_confirmed_at' => now()->timestamp])->post($post, array_diff_key($this->approval, ['confirm' => true]))->assertSessionHasErrors('confirm');
    expect($this->machine->fresh()->status)->toBe(OAuthClientStatus::Testing)->and($this->resource->fresh()->introspection_client_ids)->toBe([])->and(AuditLog::count())->toBe(0);
});

it('lists only operator configured live confidential resources and exposes safe paginated metadata', function (): void {
    $ordinary = oauthClientFixture(confidential: true);
    $public = oauthClientFixture();
    $public->forceFill(['introspection_client_ids' => []])->save();
    $suspended = approvalResourceFixture('Suspended resource');
    $suspended->forceFill(['status' => OAuthClientStatus::Suspended])->save();
    $revoked = approvalResourceFixture('Revoked resource');
    $revoked->forceFill(['revoked' => true])->save();
    foreach (range(1, 12) as $number) {
        approvalResourceFixture('Resource '.$number);
    }
    $this->actingAs($this->admin)->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    $this->get(route('admin.apps.machine.approve.confirm', $this->machine))->assertOk()->assertHeader('Cache-Control', 'no-store, private')
        ->assertViewHas('resources', fn ($resources): bool => $resources->total() === 13 && $resources->count() === 12)
        ->assertSee('Read application totals')->assertDontSee('value="openid"', false)->assertSee('No resources are selected automatically.');
    $records = app(ListMachineResources::class)->handle($this->machine);
    expect($records->first()->getAttributes())->not->toHaveKeys(['secret', 'introspection_client_ids']);
    $this->get(route('admin.apps.machine.approve.confirm', $this->machine).'?page=2')->assertOk()->assertViewHas('resources', fn ($resources): bool => $resources->count() === 1);
    $this->get(route('admin.apps.machine.approve.confirm', $this->machine).'?page[]=bad')->assertRedirect(route('admin.apps.machine.approve.confirm', $this->machine))->assertSessionHasErrors('page');
    expect($ordinary->introspection_client_ids)->toBeNull();
});

it('approves selected access atomically preserves other machines and enables real token introspection', function (): void {
    $otherMachine = approvalMachineFixture($this->owner);
    $this->resource->forceFill(['introspection_client_ids' => [$otherMachine->id]])->save();
    $unselected = approvalResourceFixture('Unselected API');
    $original = $this->machine->getRawOriginal();
    $this->actingAs($this->admin)->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    $this->get(route('admin.apps.show', $this->machine))->assertOk()->assertSee('Approve Machine application');
    $this->post(route('admin.apps.machine.approve', $this->machine), [...$this->approval, 'first_party' => true, 'secret' => 'injected', 'owner_id' => 999])
        ->assertRedirect(route('admin.apps.show', $this->machine))->assertHeader('Cache-Control', 'no-store, private');
    $machine = $this->machine->fresh();
    expect($machine->status)->toBe(OAuthClientStatus::Live)->and($machine->allowed_scopes)->toBe(['stats:read'])
        ->and($machine->secret)->toBe($original['secret'])->and($machine->owner_id)->toBe($this->owner->id)
        ->and($machine->first_party)->toBeFalse()->and($machine->grant_types)->toBe(['client_credentials'])
        ->and($this->resource->fresh()->introspection_client_ids)->toBe([$otherMachine->id, $machine->id])
        ->and($unselected->fresh()->introspection_client_ids)->toBe([]);
    $event = AuditLog::where('event', OAuthAuditEvent::MachineApproved)->sole();
    expect($event->user_id)->toBe($this->admin->id)->and($event->client_id)->toBe($machine->id);
    $token = $this->postJson('/oauth/token', ['client_id' => $machine->id, 'client_secret' => $this->machine->plainSecret, 'grant_type' => 'client_credentials', 'scope' => 'stats:read'])->assertOk()->json('access_token');
    $this->postJson('/oauth/introspect', ['client_id' => $this->resource->id, 'client_secret' => $this->resource->plainSecret, 'token' => $token])->assertOk()->assertJsonPath('active', true);
    $this->postJson('/oauth/introspect', ['client_id' => $unselected->id, 'client_secret' => $unselected->plainSecret, 'token' => $token])->assertUnauthorized();
    $this->post(route('admin.apps.machine.approve', $machine), $this->approval)->assertForbidden();
});

it('rejects malformed and identity permissions without modifying grants', function (array $overrides, string $field): void {
    $this->actingAs($this->admin)->withSession(['auth.password_confirmed_at' => now()->timestamp])
        ->post(route('admin.apps.machine.approve', $this->machine), array_replace($this->approval, $overrides))->assertSessionHasErrors($field);
    expect($this->machine->fresh()->status)->toBe(OAuthClientStatus::Testing)->and($this->resource->fresh()->introspection_client_ids)->toBe([])->and(AuditLog::count())->toBe(0);
})->with([
    [['scopes' => ['openid']], 'scopes.0'],
    [['scopes' => ['profile', 'email']], 'scopes.0'],
    [['scopes' => ['*']], 'scopes.0'],
    [['scopes' => 'stats:read'], 'scopes'],
    [['scopes' => []], 'scopes'],
    [['resources' => []], 'resources'],
    [['resources' => 'invalid'], 'resources'],
    [['resources' => [['nested']]], 'resources.0'],
    [['resources' => ['invalid']], 'resources.0'],
    [['resources' => array_fill(0, 21, '123e4567-e89b-42d3-a456-426614174000')], 'resources'],
]);

it('rejects ineligible machine state or credential ownership', function (string $kind): void {
    $changes = match ($kind) {
        'live' => ['status' => OAuthClientStatus::Live],
        'suspended' => ['status' => OAuthClientStatus::Suspended],
        'revoked' => ['revoked' => true],
        'ownerless' => ['owner_id' => null, 'owner_type' => null],
        'foreign-owner-type' => ['owner_type' => 'OtherOwner'],
        'web' => ['app_type' => OAuthAppType::Web],
        'public' => ['secret' => null],
        'wrong-grants' => ['grant_types' => ['client_credentials', 'refresh_token']],
        default => [],
    };
    $this->machine->forceFill($changes)->save();
    if ($kind === 'unverified-owner') {
        $this->owner->forceFill(['email_verified_at' => null])->save();
    }
    if ($kind === 'non-developer-owner') {
        $this->owner->forceFill(['is_developer' => false])->save();
    }
    $this->actingAs($this->admin)->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    $this->get(route('admin.apps.machine.approve.confirm', $this->machine))->assertForbidden();
    $this->post(route('admin.apps.machine.approve', $this->machine), $this->approval)->assertForbidden();
    expect(fn () => app(ApproveMachineApplication::class)->handle($this->machine, $this->approval))->toThrow(AuthorizationException::class);
    expect(AuditLog::count())->toBe(0);
})->with(['live', 'suspended', 'revoked', 'ownerless', 'foreign-owner-type', 'web', 'public', 'wrong-grants', 'unverified-owner', 'non-developer-owner']);

it('rechecks current machine and resource state after opening the form', function (): void {
    $this->actingAs($this->admin)->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    $this->get(route('admin.apps.machine.approve.confirm', $this->machine))->assertOk();
    $this->resource->forceFill(['status' => OAuthClientStatus::Suspended])->save();
    $this->post(route('admin.apps.machine.approve', $this->machine), $this->approval)->assertForbidden();
    $this->machine->newQuery()->whereKey($this->machine->id)->update(['revoked' => true]);
    expect(fn () => app(ApproveMachineApplication::class)->handle($this->machine, $this->approval))->toThrow(AuthorizationException::class);
    expect(AuditLog::count())->toBe(0)->and($this->resource->fresh()->introspection_client_ids)->toBe([]);
});

it('rejects unknown ordinary web and duplicate resources and rolls back partial writes', function (): void {
    $ordinary = oauthClientFixture(confidential: true);
    $this->actingAs($this->admin)->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    $this->post(route('admin.apps.machine.approve', $this->machine), [...$this->approval, 'resources' => [$ordinary->id]])->assertForbidden();
    $this->post(route('admin.apps.machine.approve', $this->machine), [...$this->approval, 'resources' => [$this->resource->id, (string) Str::uuid()]])->assertSessionHasErrors('resources');
    $this->post(route('admin.apps.machine.approve', $this->machine), [...$this->approval, 'resources' => [$this->resource->id, $this->resource->id]])->assertSessionHasErrors('resources.0');
    expect($this->resource->fresh()->introspection_client_ids)->toBe([])->and($ordinary->fresh()->introspection_client_ids)->toBeNull()
        ->and($this->machine->fresh()->status)->toBe(OAuthClientStatus::Testing)->and(AuditLog::count())->toBe(0);
});

it('replaces old resource access and invalidates every prior credential on reapproval', function (): void {
    $other = approvalMachineFixture($this->owner);
    $oldResource = approvalResourceFixture('Previous API');
    $oldResource->forceFill(['introspection_client_ids' => [$this->machine->id, $other->id], 'status' => OAuthClientStatus::Suspended])->save();
    $this->machine->forceFill(['status' => OAuthClientStatus::Live, 'allowed_scopes' => ['stats:read']])->save();
    $token = $this->postJson('/oauth/token', ['client_id' => $this->machine->id, 'client_secret' => $this->machine->plainSecret, 'grant_type' => 'client_credentials', 'scope' => 'stats:read'])->assertOk()->json('access_token');
    $this->machine->forceFill(['status' => OAuthClientStatus::Testing])->save();
    $this->actingAs($this->admin);
    app(ApproveMachineApplication::class)->handle($this->machine, $this->approval);
    expect($oldResource->fresh()->introspection_client_ids)->toBe([$other->id])
        ->and($this->resource->fresh()->introspection_client_ids)->toBe([$this->machine->id])->and(oauthBearerWorks($token))->toBeFalse()
        ->and(Passport::token()->newQuery()->where('client_id', $this->machine->id)->where('revoked', false)->count())->toBe(0);
});

it('rolls back activation allowlists credentials and audit if approval auditing fails', function (): void {
    AuditLog::creating(function (AuditLog $event): void {
        if ($event->event === OAuthAuditEvent::MachineApproved) {
            throw new RuntimeException('Synthetic approval audit failure');
        }
    });
    $this->actingAs($this->admin);
    expect(fn () => app(ApproveMachineApplication::class)->handle($this->machine, $this->approval))->toThrow(RuntimeException::class);
    expect($this->machine->fresh()->status)->toBe(OAuthClientStatus::Testing)->and($this->machine->fresh()->allowed_scopes)->toBe([])
        ->and($this->resource->fresh()->introspection_client_ids)->toBe([])->and(AuditLog::count())->toBe(0);
});

it('preserves earlier approvals when another machine is approved for the same resource', function (): void {
    $this->actingAs($this->admin);
    $other = approvalMachineFixture($this->owner);
    app(ApproveMachineApplication::class)->handle($this->machine, $this->approval);
    app(ApproveMachineApplication::class)->handle($other, $this->approval);
    expect($this->resource->fresh()->introspection_client_ids)->toBe([$this->machine->id, $other->id]);
    $this->admin->forceFill(['two_factor_confirmed_at' => null])->save();
    expect(Gate::allows('approveMachine', approvalMachineFixture($this->owner)))->toBeFalse();
});

it('removes old resource references beyond the chunk boundary without dropping other machines', function (): void {
    $other = approvalMachineFixture($this->owner);
    foreach (range(1, 101) as $number) {
        $resource = approvalResourceFixture('Previous resource '.$number);
        $resource->forceFill(['introspection_client_ids' => [$this->machine->id, $other->id]])->save();
    }
    $this->actingAs($this->admin);
    app(ApproveMachineApplication::class)->handle($this->machine, $this->approval);
    expect(OAuthClient::query()->whereJsonContains('introspection_client_ids', $this->machine->id)->count())->toBe(1)
        ->and(OAuthClient::query()->whereJsonContains('introspection_client_ids', $other->id)->count())->toBe(101);
});
