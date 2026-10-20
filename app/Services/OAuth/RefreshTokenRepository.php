<?php

namespace App\Services\OAuth;

use App\Enums\OAuthAuditEvent;
use App\Models\AuditLog;
use App\Models\User;
use Illuminate\Database\Eloquent\Collection;
use Laravel\Passport\Bridge\RefreshTokenRepository as PassportRefreshTokenRepository;
use Laravel\Passport\Passport;

class RefreshTokenRepository extends PassportRefreshTokenRepository
{
    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        $accessId = Passport::refreshToken()->newQuery()->whereKey($tokenId)->value('access_token_id');
        $ownerId = $accessId === null ? null : Passport::token()->newQuery()->whereKey($accessId)->value('user_id');
        if ($ownerId !== null) {
            $owner = User::whereKey($ownerId)->lockForUpdate()->first();
            if (! $owner?->accountAvailable()) {
                return true;
            }
        }
        $refresh = Passport::refreshToken()->newQuery()->whereKey($tokenId)->lockForUpdate()->first();
        if (! $refresh) {
            return true;
        }
        $access = Passport::token()->newQuery()->find($refresh->access_token_id);
        if (! $access || $access->client_id !== app(TokenContext::class)->clientId) {
            return true;
        }
        $hasLineage = is_string($access->auth_code_id) && $access->auth_code_id !== '' && $access->user_id !== null;
        if ($refresh->revoked) {
            if ($hasLineage) {
                $this->revokeFamily($access->auth_code_id, $access->client_id, $access->user_id);
            }
            AuditLog::query()->create(['user_id' => $access->user_id, 'client_id' => $access->client_id, 'event' => OAuthAuditEvent::RefreshReplayed]);

            return true;
        }
        // Legacy credentials without a family cannot safely participate in rotation.
        // Never infer a shared family from null lineage or from account/client alone.
        if (! $hasLineage) {
            return true;
        }
        app(TokenContext::class)->authCodeId = $access->auth_code_id;
        app(TokenContext::class)->authTime = $access->oidc_auth_time === null ? null : (int) $access->oidc_auth_time;
        app(TokenContext::class)->nonce = $access->oidc_nonce;
        if (in_array('openid', $access->scopes, true) && $access->oidc_auth_time === null) {
            return true;
        }

        return $refresh->expires_at <= now() || $access->revoked;
    }

    private function revokeFamily(string $authCodeId, string $clientId, int|string $userId): void
    {
        // IssueToken holds the client/user locks and commits defensive revocation even
        // when League rejects the replay. Keep spent access rows in this selection:
        // their attached refresh credentials must not survive a replay either.
        Passport::token()->newQuery()->where('auth_code_id', $authCodeId)->where('client_id', $clientId)->where('user_id', $userId)
            ->select('id')->chunkById(500, function (Collection $tokens): void {
                $identifiers = $tokens->modelKeys();
                Passport::refreshToken()->newQuery()->whereIn('access_token_id', $identifiers)->update(['revoked' => true]);
                Passport::token()->newQuery()->whereIn('id', $identifiers)->update(['revoked' => true]);
            });
    }
}
