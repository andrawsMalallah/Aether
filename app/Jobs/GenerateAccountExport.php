<?php

namespace App\Jobs;

use App\Enums\AccountExportStatus;
use App\Enums\OAuthAuditEvent;
use App\Models\AccountExport;
use App\Models\AuditLog;
use App\Models\User;
use App\Notifications\AccountExportReady;
use App\Services\AccountExportWriter;
use App\Services\PrivateStorage;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Queue\Middleware\WithoutOverlapping;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use RuntimeException;
use Throwable;

class GenerateAccountExport implements ShouldBeEncrypted, ShouldQueue
{
    use Queueable;

    public int $tries = 3;

    public int $timeout = 60;

    public int $backoff = 30;

    public bool $failOnTimeout = true;

    public function __construct(public readonly string $exportId) {}

    /** @return list<WithoutOverlapping> */
    public function middleware(): array
    {
        // Keep retries from racing artifact cleanup or notification dispatch after
        // the database transaction ends. The lock outlives this job's timeout.
        return [(new WithoutOverlapping('account-export:'.$this->exportId))->releaseAfter(30)->expireAfter(90)];
    }

    public function handle(AccountExportWriter $writer): void
    {
        $export = AccountExport::find($this->exportId);
        if ($export === null) {
            return;
        }
        $disk = PrivateStorage::disk();
        $writing = false;
        try {
            $user = DB::transaction(function () use ($export, $disk, $writer, &$writing): ?User {
                // Match deletion's user-before-export lock order; never regenerate erased data.
                $owner = User::select(['id', 'name', 'email', 'email_verified_at', 'pending_email', 'pending_email_requested_at',
                    'two_factor_confirmed_at', 'is_developer', 'is_admin', 'avatar_path', 'created_at', 'updated_at',
                    'deletion_requested_at', 'deletion_due_at', 'anonymized_at'])->whereKey($export->user_id)->lockForUpdate()->first();
                // One row lock serializes duplicate delivery, retries and expiry cleanup.
                $locked = AccountExport::whereKey($export->id)->lockForUpdate()->firstOrFail();
                if (! in_array($locked->status, [AccountExportStatus::Pending, AccountExportStatus::ReadyToNotify], true)) {
                    return null;
                }
                if (! $locked->expires_at->isFuture()) {
                    if (! $disk->delete([$locked->relativePath(), $locked->relativePath().'.partial'])) {
                        throw new RuntimeException('Expired account export could not be removed.');
                    }
                    $locked->update(['status' => AccountExportStatus::Expired]);

                    return null;
                }
                // Profile generation never selects credential hashes or second-factor secrets.
                if ($owner === null || Gate::forUser($owner)->denies('create', AccountExport::class)) {
                    $locked->update(['status' => AccountExportStatus::Failed]);

                    return null;
                }
                if ($locked->status === AccountExportStatus::ReadyToNotify) {
                    return $owner;
                }
                $stream = tmpfile();
                if ($stream === false) {
                    throw new RuntimeException('Account export storage is unavailable.');
                }
                try {
                    $writer->write($owner, $stream);
                    if (! rewind($stream)) {
                        throw new RuntimeException('Account export could not be completed.');
                    }
                    $writing = true;
                    if (! $disk->put($locked->relativePath(), $stream, ['visibility' => 'private'])) {
                        throw new RuntimeException('Account export could not be completed.');
                    }
                } finally {
                    fclose($stream);
                }
                $locked->update(['status' => AccountExportStatus::ReadyToNotify, 'completed_at' => now(), 'expires_at' => now()->addDay()]);
                AuditLog::create(['user_id' => $owner->id, 'event' => OAuthAuditEvent::AccountExported]);

                return $owner;
            });
        } catch (Throwable $exception) {
            // Only artifacts derived from this export UUID are ever removed.
            if ($writing) {
                $disk->delete([$export->relativePath(), $export->relativePath().'.partial']);
            }
            throw $exception;
        }
        // A notification transport failure must never delete an already committed export.
        if ($user !== null) {
            $user->notify(new AccountExportReady($export->id));
            // A dispatch outage leaves a retryable ready-to-notify state. Never rebuild
            // or extend the expiry of an already completed file when retrying mail.
            AccountExport::whereKey($export->id)->where('status', AccountExportStatus::ReadyToNotify)->update(['status' => AccountExportStatus::Ready]);
        }
    }

    public function failed(?Throwable $exception): void
    {
        DB::transaction(function (): void {
            $export = AccountExport::whereKey($this->exportId)->lockForUpdate()->first();
            if ($export !== null && $export->status === AccountExportStatus::Pending) {
                if (! PrivateStorage::disk()->delete([$export->relativePath(), $export->relativePath().'.partial'])) {
                    throw new RuntimeException('Account export cleanup failed.');
                }
                $export->update(['status' => AccountExportStatus::Failed]);
            }
        });
    }
}
