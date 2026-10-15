<?php

namespace Database\Seeders;

use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rules\Password;
use RuntimeException;

class AdminSeeder extends Seeder
{
    public function run(): void
    {
        $data = config('admin');
        $validator = Validator::make($data, [
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'email', 'max:255'],
            'password' => ['required', 'string', Password::min(12)->mixedCase()->numbers()->symbols()],
        ]);
        // Never put bootstrap credentials or validator input into exception context.
        if ($validator->fails()) {
            throw new RuntimeException('Provide valid admin bootstrap configuration and a strong password of at least 12 characters.');
        }
        $existing = User::query()->where('email', $data['email'])->first();
        if ($existing) {
            if (! $existing->is_admin) {
                throw new RuntimeException('An account already uses the bootstrap email. It has not been promoted or changed.');
            }

            return;
        }
        if (User::query()->where('is_admin', true)->exists()) {
            throw new RuntimeException('The first admin already exists. Additional admin promotion is a separate operation.');
        }
        $user = new User;
        $user->forceFill([
            'name' => $data['name'], 'email' => $data['email'], 'password' => $data['password'],
            'is_admin' => true, 'email_verified_at' => now(),
        ])->save();
    }
}
