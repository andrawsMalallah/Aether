<?php

namespace App\Actions\Admin;

use App\Enums\OAuthAppType;
use App\Enums\OAuthAuditEvent;
use App\Enums\OAuthClientStatus;
use App\Models\AuditLog;
use App\Models\OAuthClient;
use App\Services\OAuth\RevokeClientCredentials;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\ValidationException;

class ApproveMachineApplication
{
    public function __construct(private RevokeClientCredentials $revoke) {}

    /** @param array{scopes: list<string>, resources: list<string>, confirm?: mixed} $data */
    public function handle(OAuthClient $application, array $data): void
    {
        DB::transaction(function () use ($application, $data): void {
            $client = OAuthClient::query()->whereKey($application->id)->lockForUpdate()->firstOrFail();
            Gate::authorize('approveMachine', $client);
            if ($data['scopes'] === [] || array_diff($data['scopes'], config('oauth.machine_scopes')) !== []
                || $data['resources'] === [] || count($data['resources']) > 20 || count(array_unique($data['resources'])) !== count($data['resources'])) {
                throw ValidationException::withMessages(['resources' => 'Choose valid API permissions and resources.']);
            }

            // Lock selected and previously permitted resources together in stable ID order.
            // This preserves other machines' grants and removes old, unselected access on reapproval.
            $query = OAuthClient::query()->where('app_type', OAuthAppType::Web)->where(function (Builder $query) use ($client, $data): void {
                $query->whereIn('id', $data['resources'])->orWhereJsonContains('introspection_client_ids', $client->id);
            })->whereKeyNot($client->id)->orderBy('id')->lockForUpdate();
            $selected = [];
            $query->chunkById(100, function ($resources) use ($client, $data, &$selected): void {
                foreach ($resources as $resource) {
                    $isSelected = in_array($resource->id, $data['resources'], true);
                    if ($isSelected) {
                        Gate::authorize('approveMachineResource', $resource);
                        $selected[] = $resource->id;
                    } else {
                        Gate::authorize('administer', $resource);
                    }
                    $allowlist = array_values(array_filter($resource->introspection_client_ids ?? [], fn (string $identifier): bool => $identifier !== $client->id));
                    if ($isSelected) {
                        $allowlist[] = $client->id;
                    }
                    $resource->forceFill(['introspection_client_ids' => $allowlist]);
                    if ($resource->isDirty('introspection_client_ids')) {
                        $resource->save();
                        AuditLog::create(['user_id' => auth()->id(), 'client_id' => $resource->id, 'event' => OAuthAuditEvent::ClientUpdated]);
                    }
                }
            });
            if (count($selected) !== count($data['resources'])) {
                throw ValidationException::withMessages(['resources' => 'A selected resource is no longer available. Review your selection.']);
            }

            $this->revoke->handle($client);
            $client->forceFill(['allowed_scopes' => array_values(array_unique($data['scopes'])), 'status' => OAuthClientStatus::Live])->save();
            AuditLog::create(['user_id' => auth()->id(), 'client_id' => $client->id, 'event' => OAuthAuditEvent::MachineApproved]);
        });
    }
}
