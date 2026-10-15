<?php

namespace App\Actions\Account;

use App\Models\User;
use Illuminate\Support\Facades\Gate;

class EnableDeveloper
{
    public function handle(User $user): void
    {
        Gate::authorize('enableDeveloper', $user);
        // A privilege flag is set explicitly, never from request attributes.
        if (! $user->is_developer) {
            $user->forceFill(['is_developer' => true])->save();
        }
    }
}
