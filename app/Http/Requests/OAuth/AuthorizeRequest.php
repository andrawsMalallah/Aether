<?php

namespace App\Http\Requests\OAuth;

class AuthorizeRequest extends OAuthRequest
{
    /** @return array<string, mixed> */
    public function rules(): array
    {
        return [
            'client_id' => ['required', 'string', 'uuid'],
            'response_type' => ['required', 'string', 'in:code'],
            'redirect_uri' => ['required', 'string', 'max:2048'],
            'scope' => ['sometimes', 'string', 'max:500'],
            'state' => ['sometimes', 'string', 'max:1024'],
            'prompt' => ['sometimes', 'string', 'regex:/^(none|login|consent)( (login|consent))*$/'],
            'code_challenge' => ['required', 'string', 'regex:/^[A-Za-z0-9_-]{43}$/'],
            'code_challenge_method' => ['required', 'string', 'in:S256'],
        ];
    }
}
