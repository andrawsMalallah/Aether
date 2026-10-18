<?php

namespace App\Http\Resources;

use App\Enums\AccountExportStatus;
use App\Models\AccountExport;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/** @mixin AccountExport */
class AccountExportResource extends JsonResource
{
    /** @return array<string, mixed> */
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'status' => ! $this->expires_at->isFuture() ? AccountExportStatus::Expired->value : $this->status->value,
            'requested_at' => $this->created_at->utc()->format('Y-m-d H:i:s').' UTC',
            'completed_at' => $this->completed_at?->utc()->format('Y-m-d H:i:s').' UTC',
            'expires_at' => $this->expires_at->utc()->format('Y-m-d H:i:s').' UTC',
            'available' => $this->available(),
        ];
    }
}
