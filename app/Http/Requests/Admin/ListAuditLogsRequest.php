<?php

namespace App\Http\Requests\Admin;

use App\Enums\OAuthAuditEvent;
use App\Models\AuditLog;
use Illuminate\Contracts\Validation\Validator;
use Illuminate\Foundation\Http\FormRequest;
use Illuminate\Http\Exceptions\HttpResponseException;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;

class ListAuditLogsRequest extends FormRequest
{
    public function authorize(): bool
    {
        return Gate::allows('viewAny', AuditLog::class);
    }

    /** @return array<string, mixed> */
    public function rules(): array
    {
        $endDate = ['nullable', 'date_format:Y-m-d'];
        if (is_string($this->input('from')) && $this->input('from') !== '') {
            $endDate[] = 'after_or_equal:from';
        }

        return [
            'event' => ['nullable', 'string', Rule::enum(OAuthAuditEvent::class)],
            'client_id' => ['nullable', 'uuid'],
            'actor' => ['nullable', 'string', 'max:255'],
            'from' => ['nullable', 'date_format:Y-m-d'],
            'to' => $endDate,
            'page' => ['nullable', 'integer', 'min:1', 'max:2147483647'],
        ];
    }

    protected function failedValidation(Validator $validator): never
    {
        // Do not flash invalid query arrays into scalar controls or redirect to the invalid URL.
        throw new HttpResponseException(to_route('admin.audit.index')->withErrors($validator));
    }
}
