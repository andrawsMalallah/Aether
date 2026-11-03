<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * @property list<string> $scopes
 * @property Carbon $granted_at
 * @property Carbon|null $revoked_at
 */
class Consent extends Model
{
    public function resolveRouteBinding(mixed $value, mixed $field = null): ?Model
    {
        // A digit-only route constraint does not bound PostgreSQL bigint input.
        if (($field ?? $this->getRouteKeyName()) === $this->getKeyName()) {
            if (! is_string($value) && ! is_int($value)) {
                return null;
            }
            $value = ltrim((string) $value, '0');
            if (! ctype_digit($value) || filter_var($value, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]) === false) {
                return null;
            }
        }

        return parent::resolveRouteBinding($value, $field);
    }

    /** @return BelongsTo<OAuthClient, $this> */
    public function client(): BelongsTo
    {
        return $this->belongsTo(OAuthClient::class, 'client_id');
    }

    /** @var list<string> */
    protected $fillable = ['user_id', 'client_id', 'scopes', 'granted_at', 'revoked_at'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['scopes' => 'array', 'granted_at' => 'datetime', 'revoked_at' => 'datetime'];
    }
}
