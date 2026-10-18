<?php

namespace App\Http\Resources;

use App\Models\Consent;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/** @mixin Consent */
class ConnectedAppResource extends JsonResource
{
    /** @return array<string, mixed> */
    public function toArray(Request $request): array
    {
        $permissions = [];
        foreach ($this->scopes as $scope) {
            $permissions[] = config('oauth.scopes.'.$scope, $scope);
        }

        return [
            'id' => $this->id,
            'name' => $this->client->name,
            'unavailable' => ! $this->client->available(),
            'permissions' => $permissions,
            'granted_at' => $this->granted_at->utc()->format('Y-m-d H:i:s').' UTC',
            'datetime' => $this->granted_at->toIso8601String(),
        ];
    }
}
