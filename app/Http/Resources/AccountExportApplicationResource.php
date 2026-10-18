<?php

namespace App\Http\Resources;

use App\Models\OAuthClient;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/** @mixin OAuthClient */
class AccountExportApplicationResource extends JsonResource
{
    /** @return array<string, mixed> */
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id, 'name' => $this->name, 'type' => $this->app_type->value,
            'status' => $this->status->value, 'deleted' => $this->revoked,
            'homepage_url' => $this->homepage_url, 'redirect_uris' => $this->redirect_uris,
            'allowed_scopes' => $this->allowed_scopes ?? [],
            'created_at' => $this->created_at?->utc()->toIso8601String(),
            'updated_at' => $this->updated_at?->utc()->toIso8601String(),
        ];
    }
}
