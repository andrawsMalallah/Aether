<?php

namespace App\Http\Requests\OAuth;

class RevokeTokenRequest extends OAuthRequest
{
    /** @return array<string, mixed> */
    public function rules(): array
    {
        return [
            'token' => ['required', 'string', 'max:8192'],
            'token_type_hint' => ['sometimes', 'string', 'max:100'],
            'client_id' => ['sometimes', 'string', 'uuid'],
            'client_secret' => ['sometimes', 'string', 'max:512'],
        ];
    }
}
