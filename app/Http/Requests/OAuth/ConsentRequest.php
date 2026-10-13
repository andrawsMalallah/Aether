<?php

namespace App\Http\Requests\OAuth;

class ConsentRequest extends OAuthRequest
{
    /** @return array<string, mixed> */
    public function rules(): array
    {
        return ['auth_token' => ['required', 'string', 'max:128']];
    }
}
