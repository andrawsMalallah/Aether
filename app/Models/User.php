<?php

namespace App\Models;

use App\Notifications\ResetAccountPassword;
use App\Notifications\VerifyAccountEmail;
use Carbon\CarbonImmutable;
use Database\Factories\UserFactory;
use Illuminate\Contracts\Auth\MustVerifyEmail;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Support\Carbon;
use Laravel\Fortify\TwoFactorAuthenticatable;
use Laravel\Passport\Contracts\OAuthenticatable;
use Laravel\Passport\HasApiTokens;

/**
 * @property CarbonImmutable|null $pending_email_requested_at
 * @property Carbon|null $email_verified_at
 * @property bool $is_developer
 * @property bool $is_admin
 * @property CarbonImmutable|null $deletion_requested_at
 * @property CarbonImmutable|null $deletion_due_at
 * @property CarbonImmutable|null $anonymized_at
 */
class User extends Authenticatable implements MustVerifyEmail, OAuthenticatable
{
    /** @use HasFactory<UserFactory> */
    use HasApiTokens, HasFactory, Notifiable, TwoFactorAuthenticatable;

    /** @var list<string> */
    protected $fillable = ['name', 'email', 'password'];

    /** @var list<string> */
    protected $hidden = ['password', 'remember_token', 'two_factor_secret', 'two_factor_recovery_codes'];

    public function sendEmailVerificationNotification(): void
    {
        $this->notify(new VerifyAccountEmail);
    }

    public function sendPasswordResetNotification(mixed $token): void
    {
        $this->notify(new ResetAccountPassword($token));
    }

    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'is_admin' => 'boolean',
            'is_developer' => 'boolean',
            'email_verified_at' => 'datetime',
            'pending_email_requested_at' => 'immutable_datetime',
            'password' => 'hashed',
            'deletion_requested_at' => 'immutable_datetime',
            'deletion_due_at' => 'immutable_datetime',
            'anonymized_at' => 'immutable_datetime',
            'two_factor_confirmed_at' => 'datetime',
        ];
    }

    public function canAccessAdministration(): bool
    {
        return $this->accountAvailable() && $this->is_admin && $this->hasVerifiedEmail() && $this->hasEnabledTwoFactorAuthentication();
    }

    public function accountAvailable(): bool
    {
        return $this->deletion_requested_at === null && $this->anonymized_at === null;
    }

    public function deletionCancellable(): bool
    {
        return $this->anonymized_at === null && $this->deletion_requested_at !== null && $this->deletion_due_at?->isFuture() === true;
    }
}
