<?php

use App\Models\User;
use Database\Seeders\AdminSeeder;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config(['admin' => ['name' => 'Test administrator', 'email' => 'admin@example.test', 'password' => 'Test-only-Admin-583!']]);
});

it('bootstraps only an explicit admin and skips it without resetting credentials', function (): void {
    $this->seed(AdminSeeder::class);
    $admin = User::sole();
    expect($admin->is_admin)->toBeTrue()->and($admin->hasVerifiedEmail())->toBeTrue()
        ->and($admin->hasEnabledTwoFactorAuthentication())->toBeFalse()
        ->and(Hash::check('Test-only-Admin-583!', $admin->password))->toBeTrue()
        ->and($admin->isFillable('is_admin'))->toBeFalse();
    $hash = $admin->password;
    config(['admin.password' => 'Different-test-only-583!']);
    $this->seed(AdminSeeder::class);
    expect(User::count())->toBe(1)->and($admin->fresh()->password)->toBe($hash);
});

it('does not promote overwrite or verify an existing ordinary account', function (): void {
    $user = User::factory()->unverified()->create(['email' => 'admin@example.test']);
    $original = $user->fresh()->getRawOriginal();
    expect(fn () => $this->seed(AdminSeeder::class))->toThrow(RuntimeException::class);
    expect($user->fresh()->getRawOriginal())->toBe($original);
});

it('refuses invalid configuration without leaking its values', function (): void {
    config(['admin.password' => 'private-invalid-value', 'admin.email' => 'invalid-private-email']);
    try {
        $this->seed(AdminSeeder::class);
        $this->fail('Invalid bootstrap configuration should fail.');
    } catch (RuntimeException $exception) {
        expect($exception->getMessage())->not->toContain('private-invalid-value', 'invalid-private-email');
    }
    expect(User::count())->toBe(0);
});

it('does not create additional admins or run from ordinary database seeding', function (): void {
    $this->seed();
    expect(User::count())->toBe(0);
    User::factory()->create(['is_admin' => true]);
    expect(fn () => $this->seed(AdminSeeder::class))->toThrow(RuntimeException::class);
    expect(User::count())->toBe(1);
});
