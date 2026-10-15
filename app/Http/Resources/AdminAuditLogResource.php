<?php

namespace App\Http\Resources;

use App\Models\AuditLog;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/** @mixin AuditLog */
class AdminAuditLogResource extends JsonResource
{
    /** @return array<string, mixed> */
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            // Historical event names must remain readable even if absent from today's enum.
            'event' => $this->getRawOriginal('event'),
            'time' => $this->created_at->utc()->format('Y-m-d H:i:s'),
            'datetime' => $this->created_at->utc()->toIso8601String(),
            'actor_id' => $this->user_id,
            'actor_name' => $this->actor?->name,
            'actor_email' => $this->actor?->email,
            'client_id' => $this->client_id,
            'client_name' => $this->client?->name,
            'client_exists' => $this->client !== null,
        ];
    }
}
