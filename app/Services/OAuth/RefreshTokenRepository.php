<?php

namespace App\Services\OAuth;

use App\Enums\OAuthAuditEvent;
use App\Models\AuditLog;
use Laravel\Passport\Bridge\RefreshTokenRepository as PassportRefreshTokenRepository;
use Laravel\Passport\Passport;

class RefreshTokenRepository extends PassportRefreshTokenRepository
{
    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        $refresh = Passport::refreshToken()->newQuery()->whereKey($tokenId)->lockForUpdate()->first();
        if (! $refresh) {
            return true;
        }
        $access = Passport::token()->newQuery()->find($refresh->access_token_id);
        if (! $access || $access->client_id !== app(TokenContext::class)->clientId) {
            return true;
        }
        if ($refresh->revoked) {
            AuditLog::query()->create(['user_id' => $access->user_id, 'client_id' => $access->client_id, 'event' => OAuthAuditEvent::RefreshReplayed]);
        }
        app(TokenContext::class)->authCodeId = $access->auth_code_id;
        app(TokenContext::class)->authTime = $access->oidc_auth_time === null ? null : (int) $access->oidc_auth_time;
        app(TokenContext::class)->nonce = $access->oidc_nonce;
        if (in_array('openid', $access->scopes, true) && $access->oidc_auth_time === null) {
            return true;
        }

        return $refresh->revoked || $refresh->expires_at <= now() || $access->revoked;
    }
}
