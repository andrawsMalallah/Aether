<?php

namespace App\Http\Requests\Account;

use Illuminate\Foundation\Http\FormRequest;

class DisconnectAppRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()?->can('disconnect', $this->route('consent')) ?? false;
    }

    /** @return array<string, list<string>> */
    public function rules(): array
    {
        return ['confirm' => ['accepted']];
    }

    protected function getRedirectUrl(): string
    {
        return route('account.connected-apps.index');
    }
}
