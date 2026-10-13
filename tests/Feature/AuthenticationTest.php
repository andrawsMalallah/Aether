<?php

use App\Models\User;
use App\Notifications\ResetAccountPassword;
use App\Notifications\VerifyAccountEmail;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Notifications\SendQueuedNotifications;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\URL;

uses(RefreshDatabase::class);

it('renders all public account and legal pages', function (string $path): void {
    $this->get($path)->assertOk();
})->with(['/', '/login', '/register', '/forgot-password', '/terms', '/privacy', '/reset-password/test-token?email=test%40example.com']);

it('registers an unverified account with Argon2id and sends verification without signing in', function (): void {
    Notification::fake();
    $this->post('/register', [
        'name' => 'Account owner', 'email' => ' OWNER@EXAMPLE.COM ',
        'password' => 'Correct-Horse-42!', 'password_confirmation' => 'Correct-Horse-42!', 'terms' => '1',
    ])->assertRedirect('/login')->assertSessionHas('status');

    $user = User::where('email', 'owner@example.com')->sole();
    expect($user->email_verified_at)->toBeNull()
        ->and(password_get_info($user->password)['algoName'])->toBe('argon2id');
    $this->assertGuest();
    Notification::assertSentTo($user, VerifyAccountEmail::class);
});

it('returns the same registration response for an existing account', function (): void {
    Notification::fake();
    $attributes = ['name' => 'Owner', 'email' => 'owner@example.com', 'password' => 'Correct-Horse-42!', 'password_confirmation' => 'Correct-Horse-42!', 'terms' => '1'];
    $first = $this->post('/register', $attributes);
    $firstStatus = session('status');
    $attributes['password'] = $attributes['password_confirmation'] = 'Different-Attempt-42!';
    $second = $this->post('/register', $attributes);
    expect($second->headers->get('Location'))->toBe($first->headers->get('Location'))
        ->and(session('status'))->toBe($firstStatus)
        ->and(User::count())->toBe(1);
    expect(Hash::check('Correct-Horse-42!', User::sole()->password))->toBeTrue();
    $this->assertGuest();
    Notification::assertCount(1);
});

it('rejects breached passwords before creating an account', function (): void {
    $this->post('/register', ['name' => 'Owner', 'email' => 'owner@example.com', 'password' => 'password123', 'password_confirmation' => 'password123', 'terms' => '1'])
        ->assertSessionHasErrors('password');
    $this->assertDatabaseCount('users', 0);
});

it('requires valid registration data and accepted terms', function (): void {
    $this->post('/register', ['name' => [], 'email' => [], 'password' => 'short', 'password_confirmation' => 'different'])
        ->assertSessionHasErrors(['name', 'email', 'password', 'terms']);
});

it('logs in through Fortify and logs out', function (): void {
    $user = User::factory()->create();
    $this->post('/login', ['email' => strtoupper($user->email), 'password' => 'password'])
        ->assertRedirect('/account/profile');
    $this->assertAuthenticatedAs($user);
    $this->post('/logout')->assertRedirect('/');
    $this->assertGuest();
});

it('supports remember me', function (): void {
    $user = User::factory()->create();
    $response = $this->post('/login', ['email' => $user->email, 'password' => 'password', 'remember' => '1']);
    $response->assertRedirect('/account/profile');
    expect($user->fresh()->remember_token)->not->toBeNull();
    $response->assertCookie(auth()->guard('web')->getRecallerName());
});

it('rejects invalid login credentials without signing in', function (): void {
    $user = User::factory()->create();
    $this->post('/login', ['email' => $user->email, 'password' => 'wrong'])->assertSessionHasErrors('email');
    $this->assertGuest();
});

it('requires authentication and verification for account pages', function (): void {
    $this->get('/account/profile')->assertRedirect('/login');
    $user = User::factory()->unverified()->create();
    $this->actingAs($user)->get('/account/profile')->assertRedirect('/email/verify');
    $this->get('/email/verify')->assertOk();
});

it('verifies an account only with a signed link for its owner', function (): void {
    $user = User::factory()->unverified()->create();
    $url = URL::temporarySignedRoute('verification.verify', now()->addHour(), ['id' => $user->id, 'hash' => sha1($user->email)]);
    $this->actingAs($user)->get($url)->assertRedirect();
    expect($user->fresh()->hasVerifiedEmail())->toBeTrue();
    $this->get('/account/profile')->assertOk();
});

it('rejects expired and mismatched verification links', function (): void {
    $user = User::factory()->unverified()->create();
    $expired = URL::temporarySignedRoute('verification.verify', now()->subMinute(), ['id' => $user->id, 'hash' => sha1($user->email)]);
    $wrongHash = URL::temporarySignedRoute('verification.verify', now()->addHour(), ['id' => $user->id, 'hash' => sha1('other@example.com')]);
    $this->actingAs($user)->get($expired)->assertForbidden();
    $this->get($wrongHash)->assertForbidden();
    expect($user->fresh()->hasVerifiedEmail())->toBeFalse();
});

it('queues account emails instead of delivering them in the request', function (): void {
    Queue::fake();
    $user = User::factory()->unverified()->create();
    $user->sendEmailVerificationNotification();
    $user->sendPasswordResetNotification('test-token');
    Queue::assertPushed(SendQueuedNotifications::class, 2);
});

it('returns identical forgot-password responses for known and unknown accounts', function (): void {
    Notification::fake();
    $user = User::factory()->create();
    $known = $this->from('/forgot-password')->post('/forgot-password', ['email' => $user->email]);
    $knownStatus = session('status');
    $unknown = $this->from('/forgot-password')->post('/forgot-password', ['email' => 'unknown@example.com']);
    expect($unknown->headers->get('Location'))->toBe($known->headers->get('Location'))
        ->and(session('status'))->toBe($knownStatus);
    Notification::assertSentTo($user, ResetAccountPassword::class);
});

it('resets a password with the delivered token and rejects its replay', function (): void {
    Notification::fake();
    $user = User::factory()->create(['pending_email' => 'pending@example.com', 'pending_email_requested_at' => now()]);
    DB::table('sessions')->insert(['id' => 'other-session', 'user_id' => $user->id, 'payload' => '', 'last_activity' => now()->timestamp]);
    $this->post('/forgot-password', ['email' => $user->email]);
    $notification = Notification::sent($user, ResetAccountPassword::class)->sole();
    $this->get($notification->toMail($user)->actionUrl)->assertOk();
    $attributes = ['email' => $user->email, 'token' => $notification->token, 'password' => 'Brand-New-Password-42!', 'password_confirmation' => 'Brand-New-Password-42!'];
    $this->post('/reset-password', $attributes)->assertRedirect('/login');
    expect(Hash::check('Brand-New-Password-42!', $user->fresh()->password))->toBeTrue()
        ->and($user->fresh()->pending_email)->toBeNull();
    $this->assertDatabaseMissing('sessions', ['user_id' => $user->id]);
    $this->post('/reset-password', $attributes)->assertSessionHasErrors('email');
});

it('rejects invalid, expired, and breached-password reset attempts', function (): void {
    $user = User::factory()->create();
    $token = Password::broker()->createToken($user);
    $attributes = ['email' => $user->email, 'token' => 'wrong-token', 'password' => 'Brand-New-Password-42!', 'password_confirmation' => 'Brand-New-Password-42!'];
    $this->post('/reset-password', $attributes)->assertSessionHasErrors('email');
    $this->travel(61)->minutes();
    $attributes['token'] = $token;
    $this->post('/reset-password', $attributes)->assertSessionHasErrors('email');
    $this->travelBack();
    $attributes['password'] = $attributes['password_confirmation'] = 'password123';
    $this->post('/reset-password', $attributes)->assertSessionHasErrors('password');
    expect(Hash::check('password', $user->fresh()->password))->toBeTrue();
});

it('persists login sessions with the database driver', function (): void {
    config(['session.driver' => 'database']);
    app('session')->forgetDrivers();
    $user = User::factory()->create();
    $this->post('/login', ['email' => $user->email, 'password' => 'password'])->assertRedirect('/account/profile');
    $this->assertDatabaseHas('sessions', ['user_id' => $user->id]);
});
