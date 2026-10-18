<?php

namespace App\Http\Resources;

use App\Services\BrowserDescription;
use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

/**
 * @property string|null $user_agent
 * @property string|null $ip_address
 * @property int $last_activity
 */
class AccountExportSessionResource extends JsonResource
{
    /** @return array<string, mixed> */
    public function toArray(Request $request): array
    {
        return [
            'device' => app(BrowserDescription::class)->describe($this->user_agent ?? ''),
            'ip_address' => $this->ip_address,
            'last_active_at' => CarbonImmutable::createFromTimestampUTC($this->last_activity)->toIso8601String(),
        ];
    }
}
