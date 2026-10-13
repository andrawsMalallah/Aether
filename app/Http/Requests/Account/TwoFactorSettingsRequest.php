<?php

namespace App\Http\Requests\Account;

use Illuminate\Foundation\Http\FormRequest;

class TwoFactorSettingsRequest extends FormRequest
{
    protected $redirectRoute = 'account.security';

    public function authorize(): bool
    {
        return $this->user()?->can('update', $this->user()) ?? false;
    }

    /** @return array<string, list<string>> */
    public function rules(): array
    {
        return $this->routeIs('account.two-factor.confirm')
            ? ['code' => ['required', 'string', 'regex:/\A[0-9]{6}\z/']]
            : [];
    }
}
