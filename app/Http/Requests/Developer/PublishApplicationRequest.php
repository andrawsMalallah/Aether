<?php

namespace App\Http\Requests\Developer;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Gate;

class PublishApplicationRequest extends FormRequest
{
    public function authorize(): bool
    {
        return Gate::allows('publish', $this->route('application'));
    }

    /** @return array<string, mixed> */
    public function rules(): array
    {
        return ['confirm' => ['accepted']];
    }

    protected function getRedirectUrl(): string
    {
        return route('developer.apps.publish.confirm', $this->route('application'));
    }
}
