<?php

namespace App\Jobs;

use App\Enums\OAuthAuditEvent;
use App\Models\AccountExport;
use App\Models\AuditLog;
use App\Models\Consent;
use App\Models\OAuthClient;
use App\Models\User;
use App\Services\RevokeAccountAccess;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Queue\Middleware\WithoutOverlapping;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use Laravel\Passport\Passport;
use RuntimeException;

class FinalizeAccountDeletion implements ShouldBeEncrypted, ShouldQueue
{
    use Queueable;

    public int $tries = 3;

    public int $timeout = 60;

    public int $backoff = 60;

    public function __construct(public readonly int $userId) {}

    /** @return list<WithoutOverlapping> */
    public function middleware(): array
    {
        return [(new WithoutOverlapping('account-deletion:'.$this->userId))->releaseAfter(60)->expireAfter(180)];
    }

    public function handle(RevokeAccountAccess $revoke): void
    {
        DB::transaction(function () use ($revoke): void {
            $user = User::whereKey($this->userId)->lockForUpdate()->first();
            if (! $user || $user->anonymized_at !== null || $user->deletion_requested_at === null || $user->deletion_due_at === null || $user->deletion_due_at->isFuture()) {
                return;
            }
            // Privileged changes during the grace period require operator resolution.
            if ($user->is_admin || OAuthClient::where('owner_type', $user->getMorphClass())->where('owner_id', $user->id)->where('revoked', false)->exists()) {
                throw new RuntimeException('Account deletion requires operator review.');
            }
            $revoke->handle($user);
            AccountExport::where('user_id', $user->id)->orderBy('id')->chunkById(250, function (Collection $exports): void {
                foreach ($exports as $export) {
                    $locked = AccountExport::whereKey($export->id)->lockForUpdate()->firstOrFail();
                    if (! Storage::disk('local')->delete([$locked->relativePath(), $locked->relativePath().'.partial'])) {
                        throw new RuntimeException('Account export cleanup failed.');
                    }
                    $locked->delete();
                }
            });
            if ($user->avatar_path !== null && ! Storage::disk('local')->delete($user->avatar_path)) {
                throw new RuntimeException('Account avatar cleanup failed.');
            }
            Passport::token()->newQuery()->where('user_id', $user->id)->select('id')->chunkById(250, function (Collection $tokens): void {
                Passport::refreshToken()->newQuery()->whereIn('access_token_id', $tokens->modelKeys())->delete();
                Passport::token()->newQuery()->whereIn('id', $tokens->modelKeys())->delete();
            });
            Passport::authCode()->newQuery()->where('user_id', $user->id)->delete();
            Consent::where('user_id', $user->id)->delete();
            // Keep stable audit/client ownership references without preserving login identity.
            $user->forceFill([
                'name' => 'Deleted account', 'email' => 'deleted-'.Str::uuid().'@accounts.invalid',
                'password' => Str::random(80), 'email_verified_at' => null, 'remember_token' => null,
                'avatar_path' => null, 'pending_email' => null, 'pending_email_requested_at' => null,
                'two_factor_secret' => null, 'two_factor_recovery_codes' => null, 'two_factor_confirmed_at' => null,
                'is_developer' => false, 'is_admin' => false, 'anonymized_at' => now(), 'deletion_due_at' => null,
            ])->save();
            AuditLog::create(['user_id' => $user->id, 'event' => OAuthAuditEvent::AccountDeleted]);
        });
    }
}
