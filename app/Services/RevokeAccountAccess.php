<?php

namespace App\Services;

use App\Models\Consent;
use App\Models\User;
use Illuminate\Database\Eloquent\Collection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use Laravel\Passport\Passport;

class RevokeAccountAccess
{
    public function __construct(private AccountSessionStore $sessions) {}

    // The caller holds the user lock. Interactive issuance takes it before credential locks.
    public function handle(User $user): void
    {
        $this->sessions->forUser($user)->delete();
        $user->forceFill(['remember_token' => Str::random(60)])->save();
        DB::table('password_reset_tokens')->where('email', $user->email)->delete();
        Passport::authCode()->newQuery()->where('user_id', $user->id)->update(['revoked' => true]);
        Passport::token()->newQuery()->where('user_id', $user->id)->select('id')->chunkById(250, function (Collection $tokens): void {
            Passport::refreshToken()->newQuery()->whereIn('access_token_id', $tokens->modelKeys())->update(['revoked' => true]);
            Passport::token()->newQuery()->whereIn('id', $tokens->modelKeys())->update(['revoked' => true]);
        });
        Consent::where('user_id', $user->id)->whereNull('revoked_at')->update(['revoked_at' => now()]);
    }
}
