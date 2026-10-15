<?php

namespace App\Http\Requests\Admin;

use App\Enums\OAuthAppType;
use App\Enums\OAuthClientStatus;
use App\Models\OAuthClient;
use Illuminate\Contracts\Validation\Validator;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;

class ListApplicationsRequest extends FormRequest
{
    public function authorize(): bool
    {
        return Gate::allows('administerAny', OAuthClient::class);
    }

    /** @return array<string, mixed> */
    public function rules(): array
    {
        return [
            'search' => ['nullable', 'string', 'max:255'],
            'status' => ['nullable', 'string', Rule::in([...array_column(OAuthClientStatus::cases(), 'value'), 'revoked'])],
            'type' => ['nullable', 'string', Rule::enum(OAuthAppType::class)],
            'page' => ['nullable', 'integer', 'min:1', 'max:2147483647'],
        ];
    }

    protected function failedValidation(Validator $validator): never
    {
        // Invalid query arrays must not be flashed back into scalar form controls or redirect loops.
        throw new HttpResponseException(to_route('admin.apps.index')->withErrors($validator));
    }
}
