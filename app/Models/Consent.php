<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

/** @property list<string> $scopes */
class Consent extends Model
{
    /** @var list<string> */
    protected $fillable = ['user_id', 'client_id', 'scopes', 'granted_at', 'revoked_at'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['scopes' => 'array', 'granted_at' => 'datetime', 'revoked_at' => 'datetime'];
    }
}
