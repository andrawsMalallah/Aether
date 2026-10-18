<?php

namespace App\Actions\Account;

use App\Models\Consent;
use App\Models\User;
use Illuminate\Pagination\LengthAwarePaginator;
use Illuminate\Support\Facades\Gate;

class ListConnectedApps
{
    /** @return LengthAwarePaginator<int, Consent> */
    public function handle(User $user): LengthAwarePaginator
    {
        Gate::authorize('viewConnectedApps', $user);

        return Consent::query()->where('user_id', $user->id)->whereNull('revoked_at')
            ->select(['id', 'user_id', 'client_id', 'scopes', 'granted_at'])
            ->with('client:id,name,status,revoked')->orderByDesc('granted_at')->orderByDesc('id')->paginate(12);
    }
}
