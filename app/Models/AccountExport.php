<?php

namespace App\Models;

use App\Enums\AccountExportStatus;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property AccountExportStatus $status
 * @property Carbon $expires_at
 * @property Carbon|null $completed_at
 */
class AccountExport extends Model
{
    use HasUuids;

    /** @var list<string> */
    protected $fillable = ['user_id', 'status', 'expires_at', 'completed_at'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['status' => AccountExportStatus::class, 'expires_at' => 'datetime', 'completed_at' => 'datetime'];
    }

    public function relativePath(): string
    {
        // Generated IDs determine the path; no stored or request-supplied path is trusted.
        return 'account-exports/'.$this->getKey().'.json';
    }

    public function available(): bool
    {
        return in_array($this->status, [AccountExportStatus::Ready, AccountExportStatus::ReadyToNotify], true) && $this->expires_at->isFuture();
    }
}
