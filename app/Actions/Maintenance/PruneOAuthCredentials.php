<?php

namespace App\Actions\Maintenance;

use App\Models\OAuthClient;
use App\Models\User;
use Carbon\CarbonImmutable;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\DB;
use stdClass;

class PruneOAuthCredentials
{
    /** @return array{eligible: int, deleted: int, invalid: int, deferred: int} */
    public function handle(stdClass $candidate, CarbonImmutable $cutoff, bool $execute, int $budget, bool $code = false): array
    {
        return DB::transaction(function () use ($candidate, $cutoff, $execute, $budget, $code): array {
            $empty = ['eligible' => 0, 'deleted' => 0, 'invalid' => 0, 'deferred' => 0];
            // Match issuance: client, then owner, then refresh credentials before access.
            // Preview uses ordinary reads and never acquires row write locks.
            $clients = OAuthClient::query()->select(['id', 'grant_types'])->whereKey($candidate->client_id);
            $client = ($execute ? $clients->lockForUpdate() : $clients)->first();
            if ($client === null) {
                return array_replace($empty, ['invalid' => 1]);
            }
            if ($candidate->user_id !== null) {
                $owners = User::query()->select('id')->whereKey($candidate->user_id);
                if (($execute ? $owners->lockForUpdate() : $owners)->first() === null) {
                    return array_replace($empty, ['invalid' => 1]);
                }
            }
            $table = $code ? 'oauth_auth_codes' : 'oauth_access_tokens';
            $current = DB::table($table)->where('id', $candidate->id)->first([
                'id', 'client_id', 'user_id', 'expires_at', ...($code ? [] : ['auth_code_id']),
            ]);
            if ($current === null) {
                return $empty;
            }
            if ($current->client_id !== $candidate->client_id || $current->user_id !== $candidate->user_id) {
                return array_replace($empty, ['invalid' => 1]);
            }
            if ($current->expires_at === null) {
                return array_replace($empty, ['invalid' => 1]);
            }
            if ($current->expires_at >= $cutoff->toDateTimeString()) {
                return $empty;
            }
            if ($code) {
                if ($current->user_id === null) {
                    return array_replace($empty, ['invalid' => 1]);
                }
                $deleted = $execute ? DB::table($table)->where('id', $current->id)->where('expires_at', '<', $cutoff)->delete() : 0;

                return array_replace($empty, ['eligible' => 1, 'deleted' => $deleted]);
            }
            $family = DB::table('oauth_access_tokens');
            if (is_string($current->auth_code_id) && trim($current->auth_code_id) !== '' && $current->user_id !== null) {
                $family->where('auth_code_id', $current->auth_code_id)->where('client_id', $current->client_id)->where('user_id', $current->user_id);
            } elseif ($current->auth_code_id === null && $current->user_id === null && $client->hasGrantType('client_credentials')) {
                $family->where('id', $current->id);
            } else {
                // Legacy/ambiguous lineage must never collapse into a shared null family.
                return array_replace($empty, ['invalid' => 1]);
            }
            if ($this->unexpiredOrUnknown(clone $family, 'expires_at', $cutoff)->exists()) {
                return array_replace($empty, ['deferred' => 1]);
            }
            $refresh = DB::table('oauth_refresh_tokens')->whereIn('access_token_id', (clone $family)->select('id'));
            if ($this->unexpiredOrUnknown(clone $refresh, 'expires_at', $cutoff)->exists()) {
                return array_replace($empty, ['deferred' => 1]);
            }
            // Eligibility covers the whole family, but each transaction deletes only a
            // bounded prefix. Large expired families converge across later cursor cycles.
            $identifiers = (clone $family)->orderBy('id')->limit($budget)->pluck('id');
            $eligible = 0;
            $deleted = 0;
            foreach ($identifiers as $identifier) {
                $remaining = $budget - $eligible;
                $refreshIds = DB::table('oauth_refresh_tokens')->where('access_token_id', $identifier)
                    ->orderBy('id')->limit($remaining + 1)->pluck('id');
                $cost = $refreshIds->count() + 1;
                if ($cost > $remaining) {
                    $prefix = $refreshIds->take($remaining);
                    $eligible += $prefix->count();
                    if ($execute) {
                        $deleted += DB::table('oauth_refresh_tokens')->whereIn('id', $prefix)->delete();
                    }
                    // Keep the backing access row until all attached refresh rows
                    // are gone, even when one pair exceeds this run's delete budget.
                    break;
                }
                $eligible += $cost;
                if ($execute) {
                    $deleted += DB::table('oauth_refresh_tokens')->whereIn('id', $refreshIds)->delete();
                    $deleted += DB::table('oauth_access_tokens')->where('id', $identifier)->delete();
                }
            }

            return ['eligible' => $eligible, 'deleted' => $deleted, 'invalid' => 0, 'deferred' => $eligible === 0 ? 1 : 0];
        });
    }

    private function unexpiredOrUnknown(Builder $query, string $column, CarbonImmutable $cutoff): Builder
    {
        return $query->where(fn (Builder $condition): Builder => $condition->whereNull($column)
            ->orWhere($column, '<', '1970-01-01 00:00:00')->orWhere($column, '>=', $cutoff));
    }
}
