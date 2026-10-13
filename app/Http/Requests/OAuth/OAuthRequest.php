<?php

namespace App\Http\Requests\OAuth;

use App\Http\Resources\OAuthErrorResource;
use Illuminate\Contracts\Validation\Validator;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Http\Exceptions\HttpResponseException;

abstract class OAuthRequest extends FormRequest
{
    public function authorize(): bool
    {
        // Protocol client authentication and the resource Policy run after shape validation.
        return true;
    }

    /** @return array<string, mixed> */
    public function validationData(): array
    {
        return $this->isMethod('GET') ? $this->query->all() : $this->request->all();
    }

    public function withValidator(Validator $validator): void
    {
        $validator->after(function (Validator $validator): void {
            // A request must not mix Basic and body client credentials.
            if (! $this->isMethod('GET') && $this->getUser() !== null
                && ($this->request->has('client_id') || $this->request->has('client_secret'))) {
                $validator->errors()->add('client_id', 'Use one client authentication method.');
            }
        });
    }

    protected function failedValidation(Validator $validator): never
    {
        // Never flash protocol credentials or echo attacker-supplied parameters.
        throw new HttpResponseException($this->isMethod('GET') && ! $this->expectsJson()
            ? response()->view('oauth.error', [], 400)
            : (new OAuthErrorResource(null))->response()->setStatusCode(400));
    }
}
