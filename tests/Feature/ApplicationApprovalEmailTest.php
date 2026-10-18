<?php

use App\Enums\OAuthAuditEvent;
use App\Enums\OAuthClientStatus;
use App\Models\AuditLog;
use App\Models\Consent;
use App\Models\User;
use App\Notifications\ApplicationApproved;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Notifications\ChannelManager;
use Illuminate\Notifications\SendQueuedNotifications;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Queue;
use Laravel\Passport\Passport;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    Notification::fake();
    $this->owner = User::factory()->create();
    $this->client = oauthClientFixture();
});

it('emails only the approving user with the requested permissions and UTC approval time', function (): void {
    $this->freezeTime();
    $other = User::factory()->create();
    $this->actingAs($this->owner)->get(oauthAuthorizeUrl(oauthParameters($this->client, 'openid email')))->assertOk();
    Notification::assertNothingSent();
    $this->post('/oauth/authorize', ['auth_token' => session('authToken')])->assertRedirect();
    Notification::assertSentToTimes($this->owner, ApplicationApproved::class, 1);
    Notification::assertNotSentTo($other, ApplicationApproved::class);
    Notification::assertSentTo($this->owner, ApplicationApproved::class, function (ApplicationApproved $notification): bool {
        expect($notification->applicationName)->toBe($this->client->name)
            ->and($notification->permissions)->toBe(['Sign you in', 'See your email address'])
            ->and($notification->approvedAt)->toBe(now()->utc()->format('Y-m-d H:i:s').' UTC')
            ->and($notification->afterCommit)->toBeTrue()
            ->and($notification->toMail($this->owner)->actionUrl)->toBe(url('/account/connected-apps'));

        return true;
    });
});

it('emails on every explicit Allow including repeated forced consent scope changes and reapproval', function (): void {
    oauthCode($this, $this->owner, $this->client);
    $this->get(oauthAuthorizeUrl(oauthParameters($this->client)))->assertRedirect();
    Notification::assertSentToTimes($this->owner, ApplicationApproved::class, 1);
    $this->get(oauthAuthorizeUrl([...oauthParameters($this->client), 'prompt' => 'consent']))->assertOk();
    $this->post('/oauth/authorize', ['auth_token' => session('authToken')])->assertRedirect();
    Notification::assertSentToTimes($this->owner, ApplicationApproved::class, 2);
    oauthCode($this, $this->owner, $this->client, 'openid email');
    Notification::assertSentToTimes($this->owner, ApplicationApproved::class, 3);
    Consent::query()->update(['revoked_at' => now()]);
    oauthCode($this, $this->owner, $this->client);
    Notification::assertSentToTimes($this->owner, ApplicationApproved::class, 4);
});

it('does not email for trusted bypass but does for its explicit forced approval', function (): void {
    $this->client->forceFill(['first_party' => true])->save();
    oauthCode($this, $this->owner, $this->client);
    Notification::assertNothingSent();
    $this->get(oauthAuthorizeUrl([...oauthParameters($this->client), 'prompt' => 'consent']))->assertOk();
    $this->post('/oauth/authorize', ['auth_token' => session('authToken')])->assertRedirect();
    Notification::assertSentToTimes($this->owner, ApplicationApproved::class, 1);
});

it('does not email on denial or replayed approval', function (): void {
    $this->actingAs($this->owner)->get(oauthAuthorizeUrl(oauthParameters($this->client)))->assertOk();
    $token = session('authToken');
    $this->delete('/oauth/authorize', ['auth_token' => $token])->assertRedirect();
    $this->post('/oauth/authorize', ['auth_token' => $token])->assertForbidden();
    Notification::assertNothingSent();
    $this->get(oauthAuthorizeUrl(oauthParameters($this->client)))->assertOk();
    $approvalToken = session('authToken');
    $this->post('/oauth/authorize', ['auth_token' => $approvalToken])->assertRedirect();
    $this->post('/oauth/authorize', ['auth_token' => $approvalToken])->assertForbidden();
    Notification::assertSentToTimes($this->owner, ApplicationApproved::class, 1);
});

it('does not email when the client becomes ineligible before approval', function (): void {
    $this->actingAs($this->owner)->get(oauthAuthorizeUrl(oauthParameters($this->client)))->assertOk();
    $this->client->forceFill(['status' => OAuthClientStatus::Suspended])->save();
    $this->post('/oauth/authorize', ['auth_token' => session('authToken')])->assertForbidden();
    Notification::assertNothingSent();
});

it('does not email or persist credentials when approval auditing rolls back', function (): void {
    $this->actingAs($this->owner)->get(oauthAuthorizeUrl(oauthParameters($this->client)))->assertOk();
    AuditLog::creating(function (AuditLog $audit): void {
        if ($audit->event === OAuthAuditEvent::ConsentGranted) {
            throw new RuntimeException('Synthetic approval failure');
        }
    });
    try {
        $this->post('/oauth/authorize', ['auth_token' => session('authToken')])->assertServerError();
        expect(Consent::count())->toBe(0)->and(Passport::authCode()->newQuery()->count())->toBe(0);
        Notification::assertNothingSent();
    } finally {
        AuditLog::flushEventListeners();
    }
});

it('waits for the enclosing transaction to commit', function (): void {
    DB::beginTransaction();
    try {
        oauthCode($this, $this->owner, $this->client);
        Notification::assertNothingSent();
    } finally {
        DB::rollBack();
    }
    Notification::assertNothingSent();
    expect(Consent::count())->toBe(0);
});

it('uses the same queue infrastructure with an encrypted after-commit notification', function (): void {
    Notification::swap(new ChannelManager(app()));
    Queue::fake();
    oauthCode($this, $this->owner, $this->client);
    Queue::assertPushed(SendQueuedNotifications::class, function (SendQueuedNotifications $job): bool {
        return $job->notification instanceof ApplicationApproved && $job->shouldBeEncrypted && $job->afterCommit;
    });
    Queue::assertPushed(SendQueuedNotifications::class, 1);
});

it('renders untrusted app names as text without injecting links or exposing credentials', function (): void {
    Notification::swap(new ChannelManager(app()));
    $name = '[Click here](https://untrusted.example) <script>alert(1)</script>';
    Notification::sendNow($this->owner, new ApplicationApproved($name, ['Sign you in', 'See your name'], '2026-10-18 12:00:00 UTC'));
    $mail = app('mailer')->getSymfonyTransport()->messages()->sole()->getOriginalMessage();
    expect($mail->getHtmlBody())->toContain('Sign you in', 'See your name', '2026-10-18 12:00:00 UTC', '/account/connected-apps')
        ->not->toContain('href="https://untrusted.example', '<script>', 'client_secret', 'auth_token', 'code_verifier');
});
