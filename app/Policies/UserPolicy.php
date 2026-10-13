<?php

namespace App\Policies;

use App\Models\User;

class UserPolicy
{
    public function view(User $authenticatedUser, User $user): bool
    {
        return $authenticatedUser->is($user);
    }

    public function update(User $authenticatedUser, User $user): bool
    {
        return $authenticatedUser->is($user);
    }
}
