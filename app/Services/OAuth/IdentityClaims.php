<?php

namespace App\Services\OAuth;

use App\Models\User;

class IdentityClaims
{
    /** @param list<string> $scopes
     * @return array<string, string|bool>
     */
    public function forUser(User $user, array $scopes): array
    {
        $claims = ['sub' => (string) $user->getKey()];
        if (in_array('profile', $scopes, true)) {
            $claims['name'] = $user->name;
            // Private avatars have no relying-party-readable URL; omit the optional picture claim.
        }
        if (in_array('email', $scopes, true)) {
            $claims['email'] = $user->email;
            $claims['email_verified'] = $user->hasVerifiedEmail();
        }

        return $claims;
    }
}
