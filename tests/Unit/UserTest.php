<?php

use App\Models\User;

it('only allows approved user attributes to be mass assigned', function (): void {
    $user = new User;

    expect($user->isFillable('name'))->toBeTrue()
        ->and($user->isFillable('email'))->toBeTrue()
        ->and($user->isFillable('password'))->toBeTrue()
        ->and($user->isFillable('id'))->toBeFalse()
        ->and($user->isFillable('email_verified_at'))->toBeFalse()
        ->and($user->isFillable('is_admin'))->toBeFalse();
});

it('keeps authentication credentials out of serialized users', function (): void {
    $user = new User;
    $user->setRawAttributes([
        'name' => 'Test account',
        'password' => 'test-password-hash',
        'remember_token' => 'test-remember-token',
    ]);

    expect($user->toArray())->toBe(['name' => 'Test account']);
});
