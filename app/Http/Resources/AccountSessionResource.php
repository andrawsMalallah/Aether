<?php

namespace App\Http\Resources;

use App\Services\BrowserDescription;
use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;
use Illuminate\Support\Facades\Crypt;

/**
 * @property string $id
 * @property string|null $user_agent
 * @property string|null $ip_address
 * @property int $last_activity
 */
class AccountSessionResource extends JsonResource
{
    /** @return array<string, mixed> */
    public function toArray(Request $request): array
    {
        $current = $this->id === $request->session()->getId();
        $activity = CarbonImmutable::createFromTimestampUTC($this->last_activity);

        return [
            'current' => $current,
            'reference' => $current ? null : Crypt::encryptString($this->id),
            'device' => app(BrowserDescription::class)->describe((string) $this->user_agent),
            'ip_address' => $this->ip_address ?: 'Unavailable',
            'last_active' => $activity->format('Y-m-d H:i:s').' UTC',
            'datetime' => $activity->toIso8601String(),
        ];
    }
}
