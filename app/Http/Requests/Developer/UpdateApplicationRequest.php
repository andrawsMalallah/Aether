<?php

namespace App\Http\Requests\Developer;

use App\Models\OAuthClient;
use Illuminate\Support\Facades\Gate;

class UpdateApplicationRequest extends RegisterApplicationRequest
{
    public function authorize(): bool
    {
        return Gate::allows('update', $this->route('application'));
    }

    protected function getRedirectUrl(): string
    {
        /** @var OAuthClient $application */
        $application = $this->route('application');

        return route('developer.apps.edit', $application);
    }
}
