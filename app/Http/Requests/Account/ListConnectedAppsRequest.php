<?php

namespace App\Http\Requests\Account;

use Illuminate\Foundation\Http\FormRequest;

class ListConnectedAppsRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()?->can('viewConnectedApps', $this->user()) ?? false;
    }

    /** @return array<string, list<string>> */
    public function rules(): array
    {
        return ['page' => ['nullable', 'integer', 'min:1', 'max:2147483647']];
    }

    protected function getRedirectUrl(): string
    {
        return route('account.connected-apps.index');
    }
}
