<?php

namespace App\Http\Resources;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/** @mixin User */
class AccountExportProfileResource extends JsonResource
{
    /** @return array<string, mixed> */
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id, 'name' => $this->name, 'email' => $this->email,
            'email_verified_at' => $this->email_verified_at?->utc()->toIso8601String(),
            'pending_email' => $this->pending_email,
            'pending_email_requested_at' => $this->pending_email_requested_at?->utc()->toIso8601String(),
            'two_factor_enabled' => $this->two_factor_confirmed_at !== null,
            'is_developer' => $this->is_developer, 'is_admin' => $this->is_admin,
            'has_avatar' => $this->avatar_path !== null,
            'created_at' => $this->created_at?->utc()->toIso8601String(),
            'updated_at' => $this->updated_at?->utc()->toIso8601String(),
        ];
    }
}
