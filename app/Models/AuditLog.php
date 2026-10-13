<?php

namespace App\Models;

use App\Enums\OAuthAuditEvent;
use Illuminate\Database\Eloquent\Model;

class AuditLog extends Model
{
    public const UPDATED_AT = null;

    /** @var list<string> */
    protected $fillable = ['user_id', 'client_id', 'event'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['event' => OAuthAuditEvent::class];
    }
}
