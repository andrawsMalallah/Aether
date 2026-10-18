<?php

namespace App\Actions\Account;

use App\Models\AccountExport;
use App\Models\User;
use Illuminate\Pagination\LengthAwarePaginator;
use Illuminate\Support\Facades\Gate;

class ListAccountExports
{
    /** @return LengthAwarePaginator<int, AccountExport> */
    public function handle(User $user): LengthAwarePaginator
    {
        Gate::authorize('exportData', $user);

        return AccountExport::where('user_id', $user->id)->select(['id', 'status', 'created_at', 'completed_at', 'expires_at'])
            ->orderByDesc('created_at')->orderByDesc('id')->paginate(12);
    }
}
