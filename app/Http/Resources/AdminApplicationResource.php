<?php

namespace App\Http\Resources;

use App\Models\OAuthClient;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/** @mixin OAuthClient */
class AdminApplicationResource extends JsonResource
{
    /** @return array<string, mixed> */
    public function toArray(Request $request): array
    {
        return [
            ...(new DeveloperApplicationDetailResource($this->resource))->resolve($request),
            'owner_id' => $this->owner_id,
            'owner_type' => $this->owner_type,
        ];
    }
}
