<?php

namespace App\Policies;

use App\Models\User;

class UserPolicy
{
    public function administerAny(User $authenticatedUser): bool
    {
        return $authenticatedUser->canAccessAdministration();
    }

    public function administer(User $authenticatedUser, User $user): bool
    {
        return $authenticatedUser->canAccessAdministration();
    }

    public function enableDeveloper(User $authenticatedUser, User $user): bool
    {
        return $authenticatedUser->is($user) && $user->hasVerifiedEmail();
    }

    public function view(User $authenticatedUser, User $user): bool
    {
        return $authenticatedUser->is($user);
    }

    public function update(User $authenticatedUser, User $user): bool
    {
        return $authenticatedUser->is($user);
    }
}
