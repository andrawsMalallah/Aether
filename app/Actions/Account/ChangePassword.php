<?php

namespace App\Actions\Account;

use App\Enums\OAuthAuditEvent;
use App\Models\AuditLog;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

class ChangePassword
{
    public function handle(User $user, string $password, string $sessionId): void
    {
        DB::transaction(function () use ($user, $password, $sessionId): void {
            $user->forceFill([
                'password' => Hash::make($password),
                'remember_token' => Str::random(60),
                'pending_email' => null,
                'pending_email_requested_at' => null,
            ])->save();
            DB::table('sessions')->where('user_id', $user->id)->where('id', '!=', $sessionId)->delete();
            AuditLog::create(['user_id' => $user->id, 'event' => OAuthAuditEvent::PasswordChanged]);
        });
    }
}
