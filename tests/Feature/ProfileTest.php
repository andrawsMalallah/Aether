<?php

use App\Models\User;
use App\Notifications\EmailChangeRequested;
use App\Notifications\VerifyChangedEmail;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\URL;

uses(RefreshDatabase::class);

it('returns account validation errors to the profile after an avatar request', function (string $endpoint, array $attributes, string $errorField): void {
    $user = User::factory()->create();
    $this->actingAs($user)->withSession(['_previous' => ['url' => url('/account/avatar')]])
        ->put($endpoint, $attributes)
        ->assertRedirect('/account/profile')
        ->assertSessionHasErrors($errorField);
})->with([
    'profile' => ['/account/profile', ['name' => ''], 'name'],
    'password' => ['/account/password', ['current_password' => 'wrong'], 'current_password'],
    'email' => ['/account/email', ['email' => 'invalid'], 'email'],
]);

it('returns a successful profile update to the profile after an avatar request', function (): void {
    $user = User::factory()->create();
    $this->actingAs($user)->withSession(['_previous' => ['url' => url('/account/avatar')]])
        ->put('/account/profile', ['name' => 'Updated owner'])
        ->assertRedirect('/account/profile')->assertSessionHas('status');
});

it('updates the authenticated profile and keeps ownership fields protected', function (): void {
    $user = User::factory()->create();
    $this->actingAs($user)->from('/account/profile')->put('/account/profile', ['name' => 'Updated owner', 'email' => 'attacker@example.com', 'is_admin' => true])
        ->assertRedirect('/account/profile');
    expect($user->fresh()->name)->toBe('Updated owner')->and($user->fresh()->email)->toBe($user->email);
    $other = User::factory()->create();
    expect(Gate::forUser($user)->allows('update', $other))->toBeFalse()
        ->and(Gate::forUser($user)->allows('view', $other))->toBeFalse();
});

it('validates profile fields and stores avatars privately under generated names', function (): void {
    Storage::fake('local');
    $user = User::factory()->create();
    $this->actingAs($user)->put('/account/profile', ['name' => 'Owner', 'avatar' => UploadedFile::fake()->image('untrusted-name.jpg')])->assertRedirect();
    $path = $user->fresh()->avatar_path;
    expect($path)->toStartWith('avatars/')->not->toContain('untrusted-name');
    Storage::disk('local')->assertExists($path);
    $this->get('/account/avatar')->assertOk()->assertHeader('Cache-Control', 'no-store, private');
    $this->put('/account/profile', ['name' => [], 'avatar' => UploadedFile::fake()->create('script.svg', 10, 'image/svg+xml')])
        ->assertSessionHasErrors(['name', 'avatar']);
    $this->put('/account/profile', ['name' => 'Owner', 'avatar' => UploadedFile::fake()->image('big.jpg')->size(2049)])
        ->assertSessionHasErrors('avatar');
});

it('does not serve another account avatar', function (): void {
    Storage::fake('local');
    $user = User::factory()->create();
    $this->actingAs($user)->get('/account/avatar')->assertNotFound();
    $this->post('/logout');
    $this->get('/account/avatar')->assertRedirect('/login');
});

it('requires the current password and rejects breached replacement passwords', function (): void {
    $user = User::factory()->create();
    $this->actingAs($user)->put('/account/password', ['current_password' => 'wrong', 'password' => 'New-Password-42!', 'password_confirmation' => 'New-Password-42!'])
        ->assertSessionHasErrors('current_password');
    $this->put('/account/password', ['current_password' => 'password', 'password' => 'password123', 'password_confirmation' => 'password123'])
        ->assertSessionHasErrors('password');
    expect(Hash::check('password', $user->fresh()->password))->toBeTrue();
});

it('changes the password and revokes other sessions and pending email changes', function (): void {
    $user = User::factory()->create(['pending_email' => 'pending@example.com', 'pending_email_requested_at' => now()]);
    DB::table('sessions')->insert(['id' => 'other-device', 'user_id' => $user->id, 'payload' => '', 'last_activity' => now()->timestamp]);
    $this->actingAs($user)->put('/account/password', ['current_password' => 'password', 'password' => 'New-Password-42!', 'password_confirmation' => 'New-Password-42!'])->assertRedirect();
    expect(Hash::check('New-Password-42!', $user->fresh()->password))->toBeTrue()
        ->and($user->fresh()->pending_email)->toBeNull();
    $this->assertDatabaseMissing('sessions', ['id' => 'other-device']);
    $this->assertAuthenticatedAs($user);
});

it('retains the current email until the new address is verified and notifies both addresses', function (): void {
    Notification::fake();
    $user = User::factory()->create();
    $this->actingAs($user)->put('/account/email', ['email' => ' NEW@EXAMPLE.COM ', 'current_password' => 'password'])->assertRedirect();
    expect($user->fresh()->email)->toBe($user->email)
        ->and($user->fresh()->pending_email)->toBe('new@example.com')
        ->and($user->fresh()->hasVerifiedEmail())->toBeTrue();
    Notification::assertSentTo($user, EmailChangeRequested::class);
    Notification::assertSentOnDemand(VerifyChangedEmail::class, function (VerifyChangedEmail $notification, array $channels, object $notifiable) use ($user): bool {
        expect($notifiable->routes['mail'])->toBe('new@example.com');
        $this->get($notification->toMail($notifiable)->actionUrl)->assertRedirect('/account/profile');

        return $notification->userId === $user->id;
    });
    expect($user->fresh()->email)->toBe('new@example.com')
        ->and($user->fresh()->pending_email)->toBeNull()
        ->and($user->fresh()->hasVerifiedEmail())->toBeTrue();
});

it('rejects email changes without reauthentication and for existing addresses', function (): void {
    Notification::fake();
    $user = User::factory()->create();
    $other = User::factory()->create();
    $this->actingAs($user)->put('/account/email', ['email' => $other->email, 'current_password' => 'wrong'])->assertSessionHasErrors(['email', 'current_password']);
    Notification::assertNothingSent();
});

it('rejects another user confirmation link and expired or superseded email requests', function (): void {
    $user = User::factory()->create(['pending_email' => 'new@example.com', 'pending_email_requested_at' => now()]);
    $other = User::factory()->create();
    $url = URL::temporarySignedRoute('account.email.verify', now()->addHour(), ['user' => $user->id, 'hash' => sha1('new@example.com')]);
    $this->actingAs($other)->get($url)->assertForbidden();
    $this->actingAs($user);
    $user->forceFill(['pending_email' => 'different@example.com'])->save();
    $this->get($url)->assertForbidden();
    $user->forceFill(['pending_email' => 'new@example.com', 'pending_email_requested_at' => now()->subHours(2)])->save();
    $this->get($url)->assertForbidden();
    expect($user->fresh()->email)->toBe($user->email);
});

it('does not take an email address claimed after a change request', function (): void {
    $user = User::factory()->create(['pending_email' => 'claimed@example.com', 'pending_email_requested_at' => now()]);
    User::factory()->create(['email' => 'claimed@example.com']);
    $url = URL::temporarySignedRoute('account.email.verify', now()->addHour(), ['user' => $user->id, 'hash' => sha1('claimed@example.com')]);
    $this->actingAs($user)->get($url)->assertSessionHasErrors('email');
    expect($user->fresh()->email)->toBe($user->email);
});
