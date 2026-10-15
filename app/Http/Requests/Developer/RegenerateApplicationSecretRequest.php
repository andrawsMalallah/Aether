<?php

namespace App\Http\Requests\Developer;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Gate;

class RegenerateApplicationSecretRequest extends FormRequest
{
    public function authorize(): bool
    {
        return Gate::allows('regenerateSecret', $this->route('application'));
    }

    /** @return array<string, mixed> */
    public function rules(): array
    {
        return ['confirm' => ['accepted']];
    }

    protected function getRedirectUrl(): string
    {
        return route('developer.apps.secret.confirm', $this->route('application'));
    }
}
