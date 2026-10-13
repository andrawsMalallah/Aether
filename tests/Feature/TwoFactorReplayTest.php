<?php

use App\Services\Authentication\TwoFactorAuthenticationProvider;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Facades\Cache;
use Laravel\Fortify\Contracts\TwoFactorAuthenticationProvider as ProviderContract;
use PragmaRX\Google2FA\Google2FA;

it('binds the replay-safe provider for setup and login', function (): void {
    expect(app(ProviderContract::class))->toBeInstanceOf(TwoFactorAuthenticationProvider::class);
});

it('accepts each tolerated time step once and rejects its replay', function (int $offset): void {
    $engine = new class extends Google2FA
    {
        public int $timeStep = 1234567;

        public function getTimestamp(): int
        {
            return $this->timeStep;
        }
    };
    $provider = new TwoFactorAuthenticationProvider($engine, Cache::store());
    $secret = $engine->generateSecretKey();
    $code = $engine->oathTotp($secret, $engine->timeStep + $offset);
    expect($provider->verify($secret, $code))->toBeTrue()
        ->and($provider->verify($secret, $code))->toBeFalse();

    if ($offset === 1) {
        // A future code remains valid beyond 60 seconds; its claim must survive too.
        $this->travel(61)->seconds();
        $engine->timeStep += 2;
        expect($provider->verify($secret, $code))->toBeFalse();
    }
})->with([-1, 0, 1]);

it('rejects codes outside clock tolerance and malformed input', function (): void {
    $engine = new Google2FA;
    $provider = new TwoFactorAuthenticationProvider($engine, Cache::store());
    $secret = $engine->generateSecretKey();
    $outsideCode = $engine->oathTotp($secret, $engine->getTimestamp() + 3);
    expect($provider->verify($secret, $outsideCode))->toBeFalse()
        ->and($provider->verify($secret, []))->toBeFalse()
        ->and($provider->verify([], '123456'))->toBeFalse();
});

it('rejects a valid code when another request already claimed its step', function (): void {
    $engine = new Google2FA;
    $secret = $engine->generateSecretKey();
    $cache = Mockery::mock(Repository::class);
    $cache->shouldReceive('add')->once()->andReturn(false);
    $provider = new TwoFactorAuthenticationProvider($engine, $cache);
    expect($provider->verify($secret, $engine->getCurrentOtp($secret)))->toBeFalse();
});

it('preserves explicitly configured clock windows', function (int $window): void {
    config(['fortify-options.two-factor-authentication.window' => $window]);
    $engine = new Google2FA;
    $secret = $engine->generateSecretKey();
    $provider = new TwoFactorAuthenticationProvider($engine, Cache::store());
    $acceptedCode = $engine->oathTotp($secret, $engine->getTimestamp() + $window);
    expect($provider->verify($secret, $acceptedCode))->toBeTrue()
        ->and($provider->verify($secret, $acceptedCode))->toBeFalse();
    $outsideCode = $engine->oathTotp($secret, $engine->getTimestamp() + $window + 2);
    expect($provider->verify($secret, $outsideCode))->toBeFalse();
})->with([0, 2]);

it('does not couple users who happen to supply the same numeric code', function (): void {
    $engine = Mockery::mock(Google2FA::class);
    $engine->shouldReceive('verifyKeyNewer')->twice()->andReturn(1234567);
    $engine->shouldReceive('getWindow')->twice()->andReturn(1);
    $engine->shouldReceive('getKeyRegeneration')->twice()->andReturn(30);
    $provider = new TwoFactorAuthenticationProvider($engine, Cache::store());
    expect($provider->verify('first-account-secret', '123456'))->toBeTrue()
        ->and($provider->verify('second-account-secret', '123456'))->toBeTrue();
});
