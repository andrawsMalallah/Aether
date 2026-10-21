<?php

namespace App\Actions\OAuth;

use App\Enums\OAuthAuditEvent;
use App\Models\AuditLog;
use App\Models\OAuthClient;
use App\Services\OAuth\ReadToken;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Laravel\Passport\Passport;
use League\OAuth2\Server\Exception\OAuthServerException;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;

class RevokeToken
{
    public function __construct(private ReadToken $reader) {}

    /** @param array<string, mixed> $data */
    public function handle(Request $request, array $data): void
    {
        $clientId = $data['client_id'] ?? $request->getUser();
        $secret = $data['client_secret'] ?? $request->getPassword();
        DB::transaction(function () use ($request, $data, $clientId, $secret): void {
            // Serialize with issuance and secret rotation, then authenticate the current
            // locked client. Unavailable clients must still be able to revoke credentials.
            $client = is_string($clientId) && Str::isUuid($clientId) ? OAuthClient::query()->whereKey($clientId)->lockForUpdate()->first() : null;
            if (! $client || ($client->confidential() && (! is_string($secret) || ! Hash::check($secret, $client->secret)))) {
                throw OAuthServerException::invalidClient((new PsrHttpFactory)->createRequest($request));
            }
            Gate::authorize('revokeToken', [$client, $clientId]);
            $refresh = $this->reader->refresh($data['token']);
            $accessId = $refresh === null ? $this->reader->access($data['token']) : null;
            if ($refresh !== null) {
                if ($refresh['client_id'] !== $client->getKey()) {
                    return;
                }
                $storedRefresh = Passport::refreshToken()->newQuery()->whereKey($refresh['refresh_token_id'])->lockForUpdate()->first();
                $accessId = $storedRefresh?->access_token_id;
            }
            // Resolve ownership without an access lock. Both token forms must acquire
            // refresh locks first to avoid a cycle with refresh/account-wide revocation.
            $access = $accessId !== null ? Passport::token()->newQuery()->whereKey($accessId)->where('client_id', $client->getKey())->first() : null;
            if ($access) {
                Passport::refreshToken()->newQuery()->where('access_token_id', $access->getKey())->update(['revoked' => true]);
                $access = Passport::token()->newQuery()->whereKey($access->getKey())->where('client_id', $client->getKey())->lockForUpdate()->first();
                if ($access) {
                    $access->revoke();
                    AuditLog::query()->create(['user_id' => $access->user_id, 'client_id' => $client->getKey(), 'event' => OAuthAuditEvent::TokenRevoked]);
                }
            }
        });
    }
}
