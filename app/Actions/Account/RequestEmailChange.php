<?php

namespace App\Actions\Account;

use App\Enums\OAuthAuditEvent;
use App\Models\AuditLog;
use App\Models\User;
use App\Notifications\EmailChangeRequested;
use App\Notifications\VerifyChangedEmail;
use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;

class RequestEmailChange
{
    public function handle(User $user, string $email): void
    {
        DB::transaction(function () use ($user, $email): void {
            $requestedAt = CarbonImmutable::now();
            $user->forceFill(['pending_email' => $email, 'pending_email_requested_at' => $requestedAt])->save();
            AuditLog::create(['user_id' => $user->id, 'event' => OAuthAuditEvent::EmailChangeRequested]);
            Notification::route('mail', $email)->notify(new VerifyChangedEmail($user->id, $email, $requestedAt->addHour()));
            $user->notify(new EmailChangeRequested($email));
        });
    }
}
