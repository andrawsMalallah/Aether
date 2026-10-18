<?php

namespace App\Actions\Account;

use App\Enums\AccountExportStatus;
use App\Models\AccountExport;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;

class PruneAccountExports
{
    public function handle(): int
    {
        $removed = 0;
        AccountExport::where('expires_at', '<=', now())->where('status', '!=', AccountExportStatus::Expired)
            ->select('id')->chunkById(100, function ($exports) use (&$removed): void {
                foreach ($exports as $candidate) {
                    $removed += DB::transaction(function () use ($candidate): int {
                        $export = AccountExport::whereKey($candidate->id)->lockForUpdate()->first();
                        if ($export === null || $export->expires_at->isFuture() || $export->status === AccountExportStatus::Expired) {
                            return 0;
                        }
                        if (! Storage::disk('local')->delete([$export->relativePath(), $export->relativePath().'.partial'])) {
                            return 0;
                        }
                        $export->update(['status' => AccountExportStatus::Expired]);

                        return 1;
                    });
                }
            });

        return $removed;
    }
}
