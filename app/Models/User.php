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
use Laravel\Fortify\TwoFactorAuthenticatable;
use Laravel\Passport\Contracts\OAuthenticatable;
use Laravel\Passport\HasApiTokens;

/** @property CarbonImmutable|null $pending_email_requested_at */
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
            'email_verified_at' => 'datetime',
            'pending_email_requested_at' => 'immutable_datetime',
            'password' => 'hashed',
            'two_factor_confirmed_at' => 'datetime',
        ];
    }
}
