<?php

namespace App\Actions\Account;

use App\Models\User;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

class ConfirmEmailChange
{
    public function handle(User $user, string $hash): void
    {
        try {
            DB::transaction(function () use ($user, $hash): void {
                $lockedUser = User::whereKey($user->id)->lockForUpdate()->firstOrFail();
                abort_unless(
                    $lockedUser->pending_email !== null
                    && $lockedUser->pending_email_requested_at?->addHour()->isFuture()
                    && hash_equals(sha1($lockedUser->pending_email), $hash),
                    403,
                );
                if (User::where('email', $lockedUser->pending_email)->whereKeyNot($user->id)->exists()) {
                    throw ValidationException::withMessages(['email' => 'This address is no longer available. Request another email change.']);
                }
                $lockedUser->forceFill([
                    'email' => $lockedUser->pending_email,
                    'email_verified_at' => now(),
                    'pending_email' => null,
                    'pending_email_requested_at' => null,
                ])->save();
            });
        } catch (UniqueConstraintViolationException) {
            throw ValidationException::withMessages(['email' => 'This address is no longer available. Request another email change.']);
        }
    }
}
