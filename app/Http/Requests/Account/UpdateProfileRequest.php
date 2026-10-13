<?php

namespace App\Http\Requests\Account;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Gate;

class UpdateProfileRequest extends FormRequest
{
    // Avatar requests can replace the session's previous URL.
    protected $redirectRoute = 'account.profile';

    public function authorize(): bool
    {
        return Gate::allows('update', $this->user());
    }

    /** @return array<string, mixed> */
    public function rules(): array
    {
        return [
            'name' => ['required', 'string', 'max:255'],
            'avatar' => ['nullable', 'image', 'mimes:jpg,jpeg,png,webp', 'max:2048'],
        ];
    }
}
