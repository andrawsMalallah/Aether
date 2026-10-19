<?php

namespace App\Http\Requests\Account;

use Illuminate\Foundation\Http\FormRequest;

class CancelAccountDeletionRequest extends FormRequest
{
    protected $redirectRoute = 'account.deletion.pending';

    public function authorize(): bool
    {
        return $this->user()?->can('cancelDeletion', $this->user()) ?? false;
    }

    /** @return array<string, list<string>> */
    public function rules(): array
    {
        return ['confirm' => ['accepted']];
    }
}
