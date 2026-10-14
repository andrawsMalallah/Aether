<?php

namespace App\Services\OAuth;

use App\Enums\OAuthAuditEvent;
use App\Models\AuditLog;
use Laravel\Passport\Bridge\AuthCodeRepository as PassportAuthCodeRepository;
use Laravel\Passport\Passport;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;

class AuthCodeRepository extends PassportAuthCodeRepository
{
    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity): void
    {
        parent::persistNewAuthCode($authCodeEntity);
        $authorization = app(TokenContext::class)->authorization;
        Passport::authCode()->newQuery()->whereKey($authCodeEntity->getIdentifier())->update([
            'oidc_nonce' => $authorization?->nonce,
            'oidc_auth_time' => $authorization?->authTime,
        ]);
    }

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

        $scopes = json_decode($code->scopes ?? '[]', true, 512, JSON_THROW_ON_ERROR);
        if (in_array('openid', $scopes, true) && $code->oidc_auth_time === null) {
            return true;
        }
        app(TokenContext::class)->authTime = $code->oidc_auth_time === null ? null : (int) $code->oidc_auth_time;
        app(TokenContext::class)->nonce = $code->oidc_nonce;

        return $code->revoked || $code->expires_at <= now();
    }
}
