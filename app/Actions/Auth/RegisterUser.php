<?php

namespace App\Actions\Auth;

use App\Models\User;
use Illuminate\Auth\Events\Registered;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\Hash;

class RegisterUser
{
    /** @param array{name: string, email: string, password: string} $attributes */
    public function handle(array $attributes): void
    {
        // Hash both paths; existing accounts get the same response and no new session.
        $passwordHash = Hash::make($attributes['password']);
        if ($this->emailExists($attributes['email'])) {
            return;
        }

        try {
            $user = User::create([
                'name' => $attributes['name'],
                'email' => $attributes['email'],
                'password' => $passwordHash,
            ]);
        } catch (UniqueConstraintViolationException $exception) {
            // A concurrent registration may win the unique-email race.
            if ($this->emailExists($attributes['email'])) {
                return;
            }

            throw $exception;
        }

        event(new Registered($user));
    }

    /** @phpstan-impure */
    private function emailExists(string $email): bool
    {
        return User::where('email', $email)->exists();
    }
}
