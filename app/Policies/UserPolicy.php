<?php

namespace App\Policies;

use App\Models\User;

class UserPolicy
{
    public function requestDeletion(User $authenticatedUser, User $user): bool
    {
        return $authenticatedUser->is($user) && $user->accountAvailable() && $user->hasVerifiedEmail() && ! $user->is_admin;
    }

    public function cancelDeletion(User $authenticatedUser, User $user): bool
    {
        return $authenticatedUser->is($user) && $user->deletionCancellable();
    }

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
        return $authenticatedUser->is($user) && $user->accountAvailable() && $user->hasVerifiedEmail();
    }

    public function view(User $authenticatedUser, User $user): bool
    {
        return $authenticatedUser->is($user) && $user->accountAvailable();
    }

    public function exportData(User $authenticatedUser, User $user): bool
    {
        return $authenticatedUser->is($user) && $user->accountAvailable() && $user->hasVerifiedEmail();
    }

    public function manageSessions(User $authenticatedUser, User $user): bool
    {
        return $authenticatedUser->is($user) && $user->accountAvailable() && $user->hasVerifiedEmail();
    }

    public function viewConnectedApps(User $authenticatedUser, User $user): bool
    {
        return $authenticatedUser->is($user) && $user->accountAvailable() && $user->hasVerifiedEmail();
    }

    public function update(User $authenticatedUser, User $user): bool
    {
        return $authenticatedUser->is($user) && $user->accountAvailable();
    }
}
