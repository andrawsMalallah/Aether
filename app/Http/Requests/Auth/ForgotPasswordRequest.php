<?php

namespace App\Http\Requests\Auth;

class ForgotPasswordRequest extends EmailRequest
{
    /** @return array<string, mixed> */
    public function rules(): array
    {
        return ['email' => ['required', 'string', 'email', 'max:255']];
    }
}
