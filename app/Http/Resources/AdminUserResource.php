<?php

namespace App\Http\Resources;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/** @mixin User */
class AdminUserResource extends JsonResource
{
    /** @return array<string, mixed> */
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'email' => $this->email,
            'verified' => $this->email_verified_at !== null,
            'roles' => array_values(array_filter([$this->is_admin ? 'Administrator' : null, $this->is_developer ? 'Developer' : null])) ?: ['User'],
            'joined_at' => $this->created_at?->utc()->format('Y-m-d H:i:s'),
        ];
    }
}
