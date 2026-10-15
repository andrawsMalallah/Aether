<?php

namespace App\Http\Requests\Developer;

use App\Models\OAuthClient;
use App\Rules\WebApplicationUrl;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;

class RegisterApplicationRequest extends FormRequest
{
    protected $redirectRoute = 'developer.apps.create';

    public function authorize(): bool
    {
        return Gate::allows('create', OAuthClient::class);
    }

    protected function prepareForValidation(): void
    {
        $urls = $this->input('redirect_urls');
        // Derive the stored list from the visible form field, never a caller-supplied array.
        $this->merge(['redirect_uris' => is_string($urls) && strlen($urls) <= 22000
            ? array_values(array_filter(array_map('trim', preg_split('/\r\n|\r|\n/', $urls) ?: []), fn (string $url): bool => $url !== ''))
            : []]);
    }

    /** @return array<string, mixed> */
    public function rules(): array
    {
        return [
            'name' => ['required', 'string', 'max:255'],
            'homepage_url' => ['nullable', 'string', 'max:2048', new WebApplicationUrl],
            'redirect_urls' => ['required', 'string', 'max:22000'],
            'redirect_uris' => ['required', 'array', 'min:1', 'max:10'],
            'redirect_uris.*' => ['required', 'string', 'max:2048', 'distinct:strict', new WebApplicationUrl(true)],
            'scopes' => ['required', 'array', 'min:1', 'max:3', function (string $attribute, mixed $value, \Closure $fail): void {
                if (is_array($value) && ! in_array('openid', $value, true)) {
                    $fail('Include Sign you in to enable Aether sign-in.');
                }
            }],
            'scopes.*' => ['required', 'string', 'distinct:strict', Rule::in(['openid', 'profile', 'email'])],
        ];
    }

    /** @return array<string, string> */
    public function attributes(): array
    {
        return [
            'redirect_urls' => 'callback URLs', 'redirect_uris' => 'callback URLs',
            'redirect_uris.*' => 'callback URL', 'scopes' => 'identity permissions', 'scopes.*' => 'identity permission',
        ];
    }
}
