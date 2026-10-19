<?php

namespace App\Actions\Account;

use App\Enums\OAuthAuditEvent;
use App\Models\AuditLog;
use App\Models\OAuthClient;
use App\Models\User;
use App\Notifications\AccountDeletionRequested;
use App\Services\RevokeAccountAccess;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\ValidationException;

class RequestAccountDeletion
{
    public function __construct(private RevokeAccountAccess $revoke) {}

    public function handle(User $user): void
    {
        Gate::authorize('requestDeletion', $user);
        DB::transaction(function () use ($user): void {
            $locked = User::whereKey($user->id)->lockForUpdate()->firstOrFail();
            Gate::authorize('requestDeletion', $locked);
            if (OAuthClient::where('owner_type', $locked->getMorphClass())->where('owner_id', $locked->id)->where('revoked', false)->exists()) {
                throw ValidationException::withMessages(['confirm' => 'Delete your owned applications before requesting account deletion, including suspended applications.']);
            }
            $locked->forceFill(['deletion_requested_at' => now(), 'deletion_due_at' => now()->addDays(14),
                'pending_email' => null, 'pending_email_requested_at' => null])->save();
            $this->revoke->handle($locked);
            AuditLog::create(['user_id' => $locked->id, 'event' => OAuthAuditEvent::AccountDeletionRequested]);
            $locked->notify(new AccountDeletionRequested($locked->deletion_due_at->toISOString()));
        });
    }
}
