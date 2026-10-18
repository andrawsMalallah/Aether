<?php

namespace App\Actions\Account;

use App\Enums\OAuthAuditEvent;
use App\Models\AuditLog;
use App\Models\User;
use App\Services\AccountSessionStore;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

class RevokeSessions
{
    public function __construct(private AccountSessionStore $sessions) {}

    // A null reference selects all other sessions; only the dedicated route supplies it.
    public function handle(User $user, string $currentSessionId, ?string $sessionReference): int
    {
        Gate::authorize('manageSessions', $user);
        $targetSessionId = null;
        if ($sessionReference !== null) {
            try {
                $targetSessionId = Crypt::decryptString($sessionReference);
            } catch (DecryptException) {
                throw ValidationException::withMessages(['sessions' => 'That session is unavailable. Refresh the list and try again.']);
            }
            if ($targetSessionId === $currentSessionId) {
                throw ValidationException::withMessages(['sessions' => 'Keep this session signed in. Choose another session to revoke.']);
            }
        }

        return DB::transaction(function () use ($user, $currentSessionId, $targetSessionId): int {
            $lockedUser = User::query()->whereKey($user->id)->lockForUpdate()->firstOrFail();
            Gate::authorize('manageSessions', $lockedUser);
            $query = $this->sessions->forUser($lockedUser)->where('id', '!=', $currentSessionId);
            if ($targetSessionId !== null) {
                $query->where('id', $targetSessionId);
            }
            $deleted = $query->delete();
            if ($targetSessionId !== null && $deleted === 0) {
                throw ValidationException::withMessages(['sessions' => 'That session is unavailable. Refresh the list and try again.']);
            }
            // Deleted sessions must not silently return through an existing remember-me cookie.
            $lockedUser->setRememberToken(Str::random(60));
            $lockedUser->save();
            AuditLog::create(['user_id' => $lockedUser->id, 'event' => OAuthAuditEvent::SessionRevoked]);

            return $deleted;
        });
    }
}
