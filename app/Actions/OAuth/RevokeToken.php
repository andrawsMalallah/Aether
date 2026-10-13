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
        $client = is_string($clientId) ? OAuthClient::query()->find($clientId) : null;
        if (! $client || ($client->confidential() && (! is_string($secret) || ! Hash::check($secret, $client->secret)))) {
            throw OAuthServerException::invalidClient((new PsrHttpFactory)->createRequest($request));
        }
        Gate::authorize('revokeToken', [$client, $clientId]);
        $refresh = $this->reader->refresh($data['token']);
        $accessId = $refresh === null ? $this->reader->access($data['token']) : null;
        DB::transaction(function () use ($refresh, $accessId, $client): void {
            if ($refresh !== null && $refresh['client_id'] === $client->getKey()) {
                $storedRefresh = Passport::refreshToken()->newQuery()->whereKey($refresh['refresh_token_id'])->lockForUpdate()->first();
                $accessId = $storedRefresh?->access_token_id;
            }
            $access = $accessId !== null ? Passport::token()->newQuery()->whereKey($accessId)->where('client_id', $client->getKey())->lockForUpdate()->first() : null;
            if ($access) {
                Passport::refreshToken()->newQuery()->where('access_token_id', $access->getKey())->update(['revoked' => true]);
                $access->revoke();
                AuditLog::query()->create(['user_id' => $access->user_id, 'client_id' => $client->getKey(), 'event' => OAuthAuditEvent::TokenRevoked]);
            }
        });
    }
}
