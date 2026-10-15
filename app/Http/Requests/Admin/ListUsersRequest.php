<?php

namespace App\Http\Requests\Admin;

use App\Models\User;
use Illuminate\Contracts\Validation\Validator;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;

class ListUsersRequest extends FormRequest
{
    public function authorize(): bool
    {
        return Gate::allows('administerAny', User::class);
    }

    /** @return array<string, mixed> */
    public function rules(): array
    {
        return [
            'search' => ['nullable', 'string', 'max:255'],
            'role' => ['nullable', 'string', Rule::in(['admin', 'developer', 'user'])],
            'verification' => ['nullable', 'string', Rule::in(['verified', 'unverified'])],
            'page' => ['nullable', 'integer', 'min:1', 'max:2147483647'],
        ];
    }

    protected function failedValidation(Validator $validator): never
    {
        // Keep malformed query arrays out of scalar controls and redirect loops.
        throw new HttpResponseException(to_route('admin.users.index')->withErrors($validator));
    }
}
