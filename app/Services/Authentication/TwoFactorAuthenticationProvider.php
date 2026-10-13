<?php

namespace App\Services\Authentication;

use Illuminate\Contracts\Cache\Repository;
use Laravel\Fortify\TwoFactorAuthenticationProvider as FortifyProvider;
use PragmaRX\Google2FA\Google2FA;

class TwoFactorAuthenticationProvider extends FortifyProvider
{
    public function __construct(Google2FA $engine, private readonly Repository $replayCache)
    {
        parent::__construct($engine, $replayCache);
    }

    /**
     * The Fortify interface accepts untyped values; validate them at this boundary.
     *
     * @param  mixed  $secret  Decrypted value supplied by Fortify's callers.
     * @param  mixed  $code  Submitted value validated before calling the TOTP engine.
     */
    public function verify(#[\SensitiveParameter] mixed $secret, #[\SensitiveParameter] mixed $code): bool
    {
        if (! is_string($secret) || ! is_string($code)) {
            return false;
        }

        if (is_int($customWindow = config('fortify-options.two-factor-authentication.window'))) {
            $this->engine->setWindow($customWindow);
        }

        // A non-null prior step makes the library return the actual matched step,
        // including a future code accepted within the clock-tolerance window.
        $matchedStep = $this->engine->verifyKeyNewer($secret, $code, -1);
        if (! is_int($matchedStep)) {
            return false;
        }

        // Scope claims to the secret and step, so unrelated users do not collide.
        // Atomic add lets only one request consume a step, including parallel requests.
        $cacheKey = 'aether.2fa_steps.'.hash('sha256', $secret).'.'.$matchedStep;
        $retentionSeconds = (2 * $this->engine->getWindow() + 1) * $this->engine->getKeyRegeneration();

        return $this->replayCache->add($cacheKey, true, $retentionSeconds);
    }
}
