<?php

namespace App\Http\Requests\OAuth;

class TokenRequest extends OAuthRequest
{
    /** @return array<string, mixed> */
    public function rules(): array
    {
        return [
            'grant_type' => ['required', 'string', 'in:authorization_code,refresh_token,client_credentials'],
            'client_id' => ['sometimes', 'string', 'uuid'],
            'client_secret' => ['sometimes', 'string', 'max:512'],
            'code' => ['required_if:grant_type,authorization_code', 'string', 'max:8192'],
            'code_verifier' => ['required_if:grant_type,authorization_code', 'string', 'regex:/^[A-Za-z0-9._~-]{43,128}$/'],
            'redirect_uri' => ['required_if:grant_type,authorization_code', 'string', 'max:2048'],
            'refresh_token' => ['required_if:grant_type,refresh_token', 'string', 'max:8192'],
            'scope' => ['sometimes', 'string', 'max:500'],
        ];
    }
}
