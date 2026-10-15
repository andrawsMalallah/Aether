<?php

namespace App\Http\Requests\Admin;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Gate;

class RestoreApplicationRequest extends FormRequest
{
    public function authorize(): bool
    {
        return Gate::allows('restore', $this->route('application'));
    }

    /** @return array<string, mixed> */
    public function rules(): array
    {
        return ['confirm' => ['accepted']];
    }

    protected function getRedirectUrl(): string
    {
        return route('admin.apps.restore.confirm', $this->route('application'));
    }
}
