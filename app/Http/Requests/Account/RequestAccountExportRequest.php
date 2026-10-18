<?php

namespace App\Http\Requests\Account;

use App\Models\AccountExport;
use Illuminate\Foundation\Http\FormRequest;

class RequestAccountExportRequest extends FormRequest
{
    public function authorize(): bool
    {
        return $this->user()?->can('create', AccountExport::class) ?? false;
    }

    /** @return array<string, list<string>> */
    public function rules(): array
    {
        return ['confirm' => ['accepted']];
    }

    protected function getRedirectUrl(): string
    {
        return route('account.export.index');
    }
}
