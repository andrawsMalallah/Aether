<?php

namespace App\Policies;

use App\Models\Consent;
use App\Models\User;

class ConsentPolicy
{
    public function disconnect(User $user, Consent $consent): bool
    {
        return $user->hasVerifiedEmail() && (string) $consent->user_id === (string) $user->id && $consent->revoked_at === null;
    }
}
