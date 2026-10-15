<?php

namespace App\Http\Requests\Developer;

use App\Enums\OAuthAppType;
use App\Models\OAuthClient;
use Illuminate\Support\Facades\Gate;

class UpdateApplicationRequest extends RegisterApplicationRequest
{
    /** @return array<string, mixed> */
    public function rules(): array
    {
        $rules = parent::rules();
        // Type and credential model are fixed at registration, never changed through settings.
        unset($rules['app_type']);
        $rules['logo'] = ['nullable', 'image', 'mimes:jpg,jpeg,png,webp', 'max:2048', 'dimensions:max_width=4096,max_height=4096'];

        return $rules;
    }

    public function authorize(): bool
    {
        return Gate::allows('update', $this->route('application'));
    }

    protected function isMachineApplication(): bool
    {
        $application = $this->route('application');

        return $application instanceof OAuthClient && $application->app_type === OAuthAppType::Machine;
    }

    protected function isMobileApplication(): bool
    {
        $application = $this->route('application');

        // Use the saved type so forged settings input cannot relax Mobile callback validation.
        return $application instanceof OAuthClient && $application->app_type === OAuthAppType::Mobile;
    }

    protected function getRedirectUrl(): string
    {
        /** @var OAuthClient $application */
        $application = $this->route('application');

        return route('developer.apps.edit', $application);
    }
}
