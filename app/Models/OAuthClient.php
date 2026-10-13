<?php

namespace App\Models;

use App\Enums\OAuthAppType;
use App\Enums\OAuthClientStatus;
use Illuminate\Contracts\Auth\Authenticatable;
use Laravel\Passport\Client;
use Laravel\Passport\Scope;

/**
 * @property string|null $secret
 * @property list<string> $redirect_uris
 * @property list<string> $grant_types
 * @property list<string>|null $allowed_scopes
 */
class OAuthClient extends Client
{
    // Trust and lifecycle flags are assigned only by privileged application actions.
    /** @var list<string> */
    protected $fillable = ['name', 'redirect_uris', 'logo_path', 'homepage_url'];

    /** @var array<string, string> */
    protected $casts = [
        'grant_types' => 'array',
        'redirect_uris' => 'array',
        'revoked' => 'bool',
        'first_party' => 'bool',
        'allowed_scopes' => 'array',
        'status' => OAuthClientStatus::class,
        'app_type' => OAuthAppType::class,
    ];

    public function firstParty(): bool
    {
        return $this->first_party;
    }

    /** @param Scope[] $scopes */
    public function skipsAuthorization(Authenticatable $user, array $scopes): bool
    {
        return $this->firstParty();
    }

    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->allowed_scopes ?? [], true);
    }

    public function acceptsUser(User $user): bool
    {
        return ! $this->revoked && $user->hasVerifiedEmail() && match ($this->status) {
            OAuthClientStatus::Live => true,
            OAuthClientStatus::Testing => $this->owner_type === $user->getMorphClass()
                && (string) $this->owner_id === (string) $user->getKey(),
            default => false,
        };
    }

    public function available(): bool
    {
        return ! $this->revoked && in_array($this->status, [OAuthClientStatus::Testing, OAuthClientStatus::Live], true);
    }
}
