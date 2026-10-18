<?php

namespace App\Services;

use App\Models\User;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;

class AccountSessionStore
{
    public function forUser(User $user): Builder
    {
        $connection = config('session.connection') ?? config('database.default');
        $table = config('session.table', 'sessions');
        // User remember-token rotation and session deletion must share one transaction.
        abort_unless(config('session.driver') === 'database' && $connection === ($user->getConnectionName() ?? config('database.default'))
            && is_string($table) && $table !== '', 503, 'Session management is unavailable.');

        return DB::connection($connection)->table($table)->where('user_id', $user->id);
    }
}
