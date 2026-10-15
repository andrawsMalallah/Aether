<?php

namespace App\Actions\Admin;

use App\Enums\OAuthAppType;
use App\Enums\OAuthClientStatus;
use App\Models\OAuthClient;
use Illuminate\Pagination\LengthAwarePaginator;
use Illuminate\Support\Facades\Gate;

class ListMachineResources
{
    /** @return LengthAwarePaginator<int, OAuthClient> */
    public function handle(OAuthClient $application): LengthAwarePaginator
    {
        Gate::authorize('approveMachine', $application);

        return OAuthClient::query()->where('app_type', OAuthAppType::Web)->where('status', OAuthClientStatus::Live)
            ->where('revoked', false)->whereNotNull('secret')->where('secret', '!=', '')
            ->whereNotNull('introspection_client_ids')->select(['id', 'name', 'app_type', 'status', 'revoked'])->orderBy('id')->paginate(12);
    }
}
