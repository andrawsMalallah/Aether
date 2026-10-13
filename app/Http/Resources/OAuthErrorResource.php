<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\JsonResource;

class OAuthErrorResource extends JsonResource
{
    // OAuth protocol bodies cannot have Laravel's normal data envelope.
    public static $wrap = null;

    /** @return array<string, string> */
    public function toArray(Request $request): array
    {
        return ['error' => 'invalid_request', 'error_description' => 'The request is invalid.'];
    }
}
