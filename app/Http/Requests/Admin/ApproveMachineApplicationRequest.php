<?php

namespace App\Http\Requests\Admin;

use Illuminate\Contracts\Validation\Validator;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;

class ApproveMachineApplicationRequest extends FormRequest
{
    public function authorize(): bool
    {
        return Gate::allows('approveMachine', $this->route('application'));
    }

    /** @return array<string, mixed> */
    public function rules(): array
    {
        if ($this->isMethod('GET')) {
            return ['page' => ['nullable', 'integer', 'min:1', 'max:2147483647']];
        }

        return [
            'scopes' => ['required', 'array', 'min:1', 'max:10'],
            'scopes.*' => ['required', 'string', 'distinct:strict', Rule::in(config('oauth.machine_scopes'))],
            'resources' => ['required', 'array', 'min:1', 'max:20'],
            'resources.*' => ['required', 'uuid', 'distinct:strict'],
            'confirm' => ['accepted'],
        ];
    }

    protected function getRedirectUrl(): string
    {
        return route('admin.apps.machine.approve.confirm', $this->route('application'));
    }

    protected function failedValidation(Validator $validator): never
    {
        if ($this->isMethod('GET')) {
            // Do not redirect malformed pagination back to the same invalid query.
            throw new HttpResponseException(redirect($this->getRedirectUrl())->withErrors($validator));
        }

        throw (new ValidationException($validator))->errorBag($this->errorBag)->redirectTo($this->getRedirectUrl());
    }
}
