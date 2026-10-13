<?php

namespace App\Http\Requests\Auth;

use Illuminate\Validation\Rules\Password;

class RegisterRequest extends EmailRequest
{
    /** @return array<string, mixed> */
    public function rules(): array
    {
        return [
            'name' => ['required', 'string', 'max:255'],
            // Existence is handled after validation so it never leaks through an error.
            'email' => ['required', 'string', 'email', 'max:255'],
            'password' => ['required', 'string', 'confirmed', Password::defaults()],
            'terms' => ['accepted'],
        ];
    }
}
