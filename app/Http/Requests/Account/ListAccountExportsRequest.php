<?php

namespace App\Http\Requests\Account;

use App\Models\AccountExport;
use Illuminate\Foundation\Http\FormRequest;

class ListAccountExportsRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()?->can('viewAny', AccountExport::class) ?? false;
    }

    /** @return array<string, list<string>> */
    public function rules(): array
    {
        return ['page' => ['nullable', 'integer', 'min:1', 'max:2147483647']];
    }

    protected function getRedirectUrl(): string
    {
        return route('account.export.index');
    }
}
