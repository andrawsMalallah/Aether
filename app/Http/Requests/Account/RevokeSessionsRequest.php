<?php

namespace App\Http\Requests\Account;

use Illuminate\Foundation\Http\FormRequest;

class RevokeSessionsRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()?->can('manageSessions', $this->user()) ?? false;
    }

    /** @return array<string, list<string>> */
    public function rules(): array
    {
        return [
            'confirm' => ['accepted'],
            'session_reference' => $this->routeIs('account.sessions.revoke')
                ? ['required', 'string', 'max:4096'] : ['prohibited'],
        ];
    }

    protected function getRedirectUrl(): string
    {
        return route('account.sessions.index');
    }
}
