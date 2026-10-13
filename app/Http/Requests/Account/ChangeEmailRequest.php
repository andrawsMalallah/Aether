<?php

namespace App\Http\Requests\Account;

use App\Http\Requests\Auth\EmailRequest;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;

class ChangeEmailRequest extends EmailRequest
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
            'email' => ['required', 'string', 'email', 'max:255', Rule::unique('users', 'email')],
            'current_password' => ['required', 'string', 'current_password:web'],
        ];
    }
}
