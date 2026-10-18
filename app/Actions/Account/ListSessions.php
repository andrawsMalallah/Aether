<?php

namespace App\Actions\Account;

use App\Models\User;
use App\Services\AccountSessionStore;
use Illuminate\Pagination\LengthAwarePaginator;
use Illuminate\Support\Facades\Gate;

class ListSessions
{
    public function __construct(private AccountSessionStore $sessions) {}

    /** @return LengthAwarePaginator<int, \stdClass> */
    public function handle(User $user, string $currentSessionId): LengthAwarePaginator
    {
        Gate::authorize('manageSessions', $user);

        return $this->sessions->forUser($user)->select(['id', 'ip_address', 'user_agent', 'last_activity'])
            ->where('last_activity', '>=', now()->subMinutes((int) config('session.lifetime'))->timestamp)
            ->orderByRaw('case when id = ? then 0 else 1 end', [$currentSessionId])
            ->orderByDesc('last_activity')->orderBy('id')->paginate(12);
    }
}
