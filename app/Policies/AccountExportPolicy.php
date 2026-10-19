<?php

namespace App\Policies;

use App\Models\AccountExport;
use App\Models\User;

class AccountExportPolicy
{
    public function viewAny(User $user): bool
    {
        return $user->accountAvailable() && $user->hasVerifiedEmail();
    }

    public function create(User $user): bool
    {
        return $user->accountAvailable() && $user->hasVerifiedEmail();
    }

    public function download(User $user, AccountExport $export): bool
    {
        return $user->accountAvailable() && $user->hasVerifiedEmail() && (string) $export->user_id === (string) $user->id;
    }
}
