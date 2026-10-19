<?php

namespace App\Actions\Account;

use App\Enums\OAuthAuditEvent;
use App\Models\AuditLog;
use App\Models\User;
use App\Services\AccountDeletionAccess;
use App\Services\RevokeAccountAccess;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;

class CancelAccountDeletion
{
    public function handle(Request $request): void
    {
        DB::transaction(function () use ($request): void {
            $user = User::whereKey($request->user()->getAuthIdentifier())->lockForUpdate()->firstOrFail();
            Gate::authorize('cancelDeletion', $user);
            abort_unless(app(AccountDeletionAccess::class)->recentlyAuthenticated($request, $user), 403);
            // Cancellation cannot restore credentials or sessions from before the request.
            app(RevokeAccountAccess::class)->handle($user);
            $user->forceFill(['deletion_requested_at' => null, 'deletion_due_at' => null])->save();
            AuditLog::create(['user_id' => $user->id, 'event' => OAuthAuditEvent::AccountDeletionCancelled]);
        });
    }
}
