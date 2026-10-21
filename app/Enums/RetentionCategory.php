<?php

namespace App\Enums;

enum RetentionCategory: string
{
    case Audit = 'audit';
    case OAuth = 'oauth';
    case Codes = 'codes';
    case Sessions = 'sessions';
    case Resets = 'resets';
    case FailedJobs = 'failed-jobs';

    public function table(): string
    {
        return match ($this) {
            self::Audit => 'audit_logs',
            self::OAuth => 'oauth_access_tokens',
            self::Codes => 'oauth_auth_codes',
            self::Sessions => 'sessions',
            self::Resets => 'password_reset_tokens',
            self::FailedJobs => 'failed_jobs',
        };
    }

    public function key(): string
    {
        return $this === self::Resets ? 'email' : 'id';
    }

    public function timestamp(): string
    {
        return match ($this) {
            self::Audit, self::Resets => 'created_at',
            self::OAuth, self::Codes => 'expires_at',
            self::Sessions => 'last_activity',
            self::FailedJobs => 'failed_at',
        };
    }
}
