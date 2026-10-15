<?php

namespace App\Http\Resources;

use App\Enums\OAuthAppType;
use App\Enums\OAuthClientStatus;
use App\Models\OAuthClient;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/** @mixin OAuthClient */
class DeveloperApplicationResource extends JsonResource
{
    /** @return array{id: string, name: string, type: string, status: string} */
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'type' => match ($this->app_type) {
                OAuthAppType::Web => 'Web application',
                OAuthAppType::Spa => 'Browser application',
                OAuthAppType::Mobile => 'Mobile application',
                OAuthAppType::Machine => 'Machine client',
            },
            'status' => $this->revoked ? 'Revoked' : match ($this->status) {
                OAuthClientStatus::Testing => 'Testing',
                OAuthClientStatus::Live => 'Live',
                OAuthClientStatus::Suspended => 'Suspended',
            },
        ];
    }
}
