<?php

namespace App\Services;

use App\Http\Resources\AccountExportApplicationResource;
use App\Http\Resources\AccountExportAuditResource;
use App\Http\Resources\AccountExportConsentResource;
use App\Http\Resources\AccountExportProfileResource;
use App\Http\Resources\AccountExportSessionResource;
use App\Models\AuditLog;
use App\Models\Consent;
use App\Models\OAuthClient;
use App\Models\User;
use Illuminate\Http\Request;
use RuntimeException;

class AccountExportWriter
{
    /** @param resource $stream */
    public function write(User $user, mixed $stream): void
    {
        $request = new Request;
        $sessionsSupported = config('session.driver') === 'database'
            && (config('session.connection') ?? config('database.default')) === ($user->getConnectionName() ?? config('database.default'));
        $this->writeJson($stream, '{"format_version":1,"generated_at":');
        $this->writeValue($stream, now()->utc()->toIso8601String());
        $this->writeJson($stream, ',"notes":');
        $this->writeValue($stream, [
            'Data reflects records available during generation, not a historical archive.',
            'Profile images and application logos are not included in this JSON export.',
            'Session device names are estimates; raw session identifiers and user agents are excluded.',
            'Audit references identify the account involved, not always the requester.',
            $sessionsSupported ? 'Recent database sessions are included.' : 'Session metadata is unavailable for this session store.',
        ]);
        $this->writeJson($stream, ',"profile":');
        $this->writeValue($stream, (new AccountExportProfileResource($user))->resolve($request));
        $this->writeJson($stream, ',"connected_apps":');
        $this->writeRows($stream, Consent::where('user_id', $user->id)
            ->select(['id', 'client_id', 'scopes', 'granted_at', 'revoked_at'])->with('client:id,name')->lazyById(250),
            fn (Consent $consent): array => (new AccountExportConsentResource($consent))->resolve($request));
        $this->writeJson($stream, ',"owned_applications":');
        $this->writeRows($stream, OAuthClient::where('owner_type', $user->getMorphClass())->where('owner_id', $user->id)
            ->select(['id', 'name', 'app_type', 'status', 'revoked', 'homepage_url', 'redirect_uris', 'allowed_scopes', 'created_at', 'updated_at'])->lazyById(250),
            fn (OAuthClient $client): array => (new AccountExportApplicationResource($client))->resolve($request));
        $this->writeJson($stream, ',"active_sessions":');
        $sessions = $sessionsSupported ? app(AccountSessionStore::class)->forUser($user)
            ->select(['id', 'ip_address', 'user_agent', 'last_activity'])
            ->where('last_activity', '>=', now()->subMinutes((int) config('session.lifetime'))->timestamp)->lazyById(250) : [];
        $this->writeRows($stream, $sessions, fn (\stdClass $session): array => (new AccountExportSessionResource($session))->resolve($request));
        $this->writeJson($stream, ',"audit_history":');
        $this->writeRows($stream, AuditLog::where('user_id', $user->id)->select(['id', 'client_id', 'event', 'created_at'])->lazyById(250),
            fn (AuditLog $audit): array => (new AccountExportAuditResource($audit))->resolve($request));
        $this->writeJson($stream, '}');
    }

    /**
     * @param  resource  $stream
     * @param  iterable<mixed>  $rows
     * @param  callable(mixed): array<string, mixed>  $transform
     */
    private function writeRows(mixed $stream, iterable $rows, callable $transform): void
    {
        $this->writeJson($stream, '[');
        $first = true;
        foreach ($rows as $row) {
            if (! $first) {
                $this->writeJson($stream, ',');
            }
            $this->writeValue($stream, $transform($row));
            $first = false;
        }
        $this->writeJson($stream, ']');
    }

    /** @param resource $stream */
    private function writeValue(mixed $stream, mixed $value): void
    {
        $this->writeJson($stream, json_encode($value, JSON_THROW_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
    }

    /** @param resource $stream */
    private function writeJson(mixed $stream, string $content): void
    {
        while ($content !== '') {
            $written = fwrite($stream, $content);
            if ($written === false || $written === 0) {
                throw new RuntimeException('Account export could not be written.');
            }
            $content = substr($content, $written);
        }
    }
}
