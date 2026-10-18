<?php

namespace App\Http\Resources;

use App\Models\Consent;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/** @mixin Consent */
class AccountExportConsentResource extends JsonResource
{
    /** @return array<string, mixed> */
    public function toArray(Request $request): array
    {
        return [
            'application_id' => $this->client_id, 'application_name' => $this->client?->name,
            'scopes' => $this->scopes,
            'granted_at' => $this->granted_at->utc()->toIso8601String(),
            'revoked_at' => $this->revoked_at?->utc()->toIso8601String(),
        ];
    }
}
