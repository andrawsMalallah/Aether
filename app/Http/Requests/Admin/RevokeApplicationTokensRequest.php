<?php

namespace App\Http\Requests\Admin;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Gate;

class RevokeApplicationTokensRequest extends FormRequest
{
    public function authorize(): bool
    {
        return Gate::allows('revokeTokens', $this->route('application'));
    }

    /** @return array<string, mixed> */
    public function rules(): array
    {
        return ['confirm' => ['accepted']];
    }

    protected function getRedirectUrl(): string
    {
        return route('admin.apps.tokens.revoke.confirm', $this->route('application'));
    }
}
