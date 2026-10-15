<?php

namespace App\Actions\Developer;

use App\Models\OAuthClient;
use App\Models\User;
use Illuminate\Pagination\LengthAwarePaginator;
use Illuminate\Support\Facades\Gate;

class ListApplications
{
    /** @return LengthAwarePaginator<int, OAuthClient> */
    public function handle(User $user): LengthAwarePaginator
    {
        Gate::authorize('viewAny', OAuthClient::class);

        return OAuthClient::query()
            ->where('owner_type', $user->getMorphClass())->where('owner_id', $user->getKey())
            ->where('revoked', false)
            ->select(['id', 'name', 'logo_path', 'app_type', 'status', 'revoked'])
            ->orderBy('id')->paginate(12);
    }
}
