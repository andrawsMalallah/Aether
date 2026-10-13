<?php

namespace App\Http\Requests\Account;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rules\Password;

class ChangePasswordRequest extends FormRequest
{
    protected $redirectRoute = 'account.profile';

    public function authorize(): bool
    {
        return Gate::allows('update', $this->user());
    }

    /** @return array<string, mixed> */
    public function rules(): array
    {
        return [
            'current_password' => ['required', 'string', 'current_password:web'],
            'password' => ['required', 'string', 'confirmed', Password::defaults()],
        ];
    }
}
