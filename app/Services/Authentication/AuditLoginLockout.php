<?php

namespace App\Services\Authentication;

use App\Enums\OAuthAuditEvent;
use App\Models\AuditLog;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Illuminate\Http\Request;

class AuditLoginLockout
{
    /** @param array<string, int|string> $headers */
    public function respond(Request $request, array $headers): never
    {
        // Login throttling cannot establish an actor from the submitted email.
        // A challenged account ID, unlike request input, is held server-side.
        $userId = $request->routeIs('two-factor.login.store') ? $request->session()->get('login.id') : null;
        AuditLog::create(['user_id' => is_int($userId) || is_string($userId) ? $userId : null, 'event' => OAuthAuditEvent::LoginLockedOut]);

        // Preserve Laravel's standard 429 handling and all original throttle headers.
        throw new ThrottleRequestsException('Too Many Attempts.', null, $headers);
    }
}
