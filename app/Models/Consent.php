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
