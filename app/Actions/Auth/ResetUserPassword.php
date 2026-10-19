<?php

namespace App\Actions\Auth;

use App\Models\User;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;

class ResetUserPassword
{
    /** @param array{email: string, token: string, password: string, password_confirmation: string} $attributes */
    public function handle(array $attributes): string
    {
        // The account change, consumed broker link and audit record succeed together.
        return DB::transaction(fn (): string => Password::broker()->reset($attributes, function (User $user, string $password): void {
            $user = User::whereKey($user->id)->lockForUpdate()->firstOrFail();
            abort_unless($user->accountAvailable(), 403);
            $user->forceFill([
                'password' => Hash::make($password),
                'remember_token' => Str::random(60),
                'pending_email' => null,
                'pending_email_requested_at' => null,
            ])->save();
            DB::table('sessions')->where('user_id', $user->id)->delete();
            event(new PasswordReset($user));
        }));
    }
}
