<?php

namespace App\Services\OAuth;

use App\Enums\OAuthAuditEvent;
use App\Models\AuditLog;
use Laravel\Passport\Bridge\AuthCodeRepository as PassportAuthCodeRepository;
use Laravel\Passport\Passport;

class AuthCodeRepository extends PassportAuthCodeRepository
{
    public function isAuthCodeRevoked(string $codeId): bool
    {
        // Token exchanges hold this row lock until token creation and consumption commit.
        $code = Passport::authCode()->newQuery()->whereKey($codeId)->lockForUpdate()->first();
        if (! $code || $code->client_id !== app(TokenContext::class)->clientId) {
            return true;
        }
        if ($code->revoked) {
            $tokens = Passport::token()->newQuery()->where('auth_code_id', $codeId);
            Passport::refreshToken()->newQuery()->whereIn('access_token_id', (clone $tokens)->select('id'))->update(['revoked' => true]);
            $tokens->update(['revoked' => true]);
            AuditLog::query()->create(['user_id' => $code->user_id, 'client_id' => $code->client_id, 'event' => OAuthAuditEvent::CodeReplayed]);
        }

        return $code->revoked || $code->expires_at <= now();
    }
}
