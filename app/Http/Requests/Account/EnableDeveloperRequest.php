<?php

namespace App\Http\Requests\Account;

use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Support\Facades\Gate;

class EnableDeveloperRequest extends FormRequest
{
    public function authorize(): bool
    {
        return Gate::allows('enableDeveloper', $this->user());
    }

    /** @return array<string, mixed> */
    public function rules(): array
    {
        return [];
    }
}
