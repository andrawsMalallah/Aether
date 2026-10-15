<?php

namespace App\Http\Resources;

use App\Models\OAuthClient;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/** @mixin OAuthClient */
class DeveloperApplicationDetailResource extends JsonResource
{
    /** @return array<string, mixed> */
    public function toArray(Request $request): array
    {
        return [
            ...(new DeveloperApplicationResource($this->resource))->resolve($request),
            'homepage_url' => $this->homepage_url,
            'redirect_uris' => $this->redirect_uris,
            'scopes' => array_intersect_key(config('oauth.scopes'), array_flip($this->allowed_scopes ?? [])),
        ];
    }
}
