<?php

namespace App\Actions\Account;

use App\Enums\AccountExportStatus;
use App\Jobs\GenerateAccountExport;
use App\Models\AccountExport;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\ValidationException;

class RequestAccountExport
{
    public function handle(User $user): AccountExport
    {
        Gate::authorize('exportData', $user);

        return DB::transaction(function () use ($user): AccountExport {
            $lockedUser = User::whereKey($user->id)->lockForUpdate()->firstOrFail();
            Gate::authorize('exportData', $lockedUser);
            $existing = AccountExport::where('user_id', $lockedUser->id)
                ->where(function ($query): void {
                    $query->where('created_at', '>', now()->subHour())
                        ->orWhere(fn ($query) => $query->where('status', AccountExportStatus::Pending)->where('expires_at', '>', now()));
                })->exists();
            if ($existing) {
                throw ValidationException::withMessages(['confirm' => 'An export was requested recently or is still being prepared. You can request one per hour.']);
            }
            $export = AccountExport::create(['user_id' => $lockedUser->id, 'status' => AccountExportStatus::Pending, 'expires_at' => now()->addDay()]);
            GenerateAccountExport::dispatch($export->id)->afterCommit();

            return $export;
        });
    }
}
