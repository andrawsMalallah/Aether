<?php

namespace App\Services;

use App\Models\User;
use Illuminate\Http\Request;

class AccountDeletionAccess
{
    public function recentlyAuthenticated(Request $request, User $user): bool
    {
        $proof = $request->session()->get('deletion.login');

        return $user->deletionCancellable() && is_array($proof)
            && ($proof['user_id'] ?? null) === (string) $user->id
            && ($proof['requested_at'] ?? null) === $user->deletion_requested_at?->toISOString()
            && is_int($proof['time'] ?? null) && $proof['time'] > now()->subMinutes(5)->timestamp
            && $proof['time'] <= now()->timestamp;
    }
}
