<?php

namespace App\Http\Resources;

use App\Models\AuditLog;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/** @mixin AuditLog */
class AccountExportAuditResource extends JsonResource
{
    /** @return array<string, mixed> */
    public function toArray(Request $request): array
    {
        return [
            'event' => $this->getRawOriginal('event'), 'application_id' => $this->client_id,
            'created_at' => $this->created_at->utc()->toIso8601String(),
        ];
    }
}
