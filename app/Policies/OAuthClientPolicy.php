<?php

namespace App\Policies;

use App\Enums\OAuthAppType;
use App\Enums\OAuthClientStatus;
use App\Models\OAuthClient;
use App\Models\User;

class OAuthClientPolicy
{
    public function administerAny(User $user): bool
    {
        return $user->canAccessAdministration();
    }

    public function administer(User $user, OAuthClient $client): bool
    {
        return $this->administerAny($user);
    }

    public function suspend(User $user, OAuthClient $client): bool
    {
        return $this->administer($user, $client) && $client->available();
    }

    public function restore(User $user, OAuthClient $client): bool
    {
        return $this->administer($user, $client) && ! $client->revoked && $client->status === OAuthClientStatus::Suspended;
    }

    public function create(User $user): bool
    {
        return $this->viewAny($user);
    }

    public function approveMachine(User $user, OAuthClient $client): bool
    {
        if (! $this->administer($user, $client) || $client->revoked || $client->status !== OAuthClientStatus::Testing
            || $client->app_type !== OAuthAppType::Machine || ! $client->supportsDeveloperManagement()
            || $client->owner_type !== (new User)->getMorphClass() || $client->owner_id === null) {
            return false;
        }

        return User::query()->whereKey($client->owner_id)->where('is_developer', true)->whereNotNull('email_verified_at')->exists();
    }

    public function approveMachineResource(User $user, OAuthClient $resource): bool
    {
        // A non-null list, including an empty one, marks an operator-configured resource.
        return $this->administer($user, $resource) && $resource->available() && $resource->status === OAuthClientStatus::Live
            && $resource->app_type === OAuthAppType::Web && $resource->confidential() && is_array($resource->introspection_client_ids);
    }

    public function view(User $user, OAuthClient $client): bool
    {
        return $this->viewAny($user) && ! $client->revoked && $client->owner_type === $user->getMorphClass()
            && (string) $client->owner_id === (string) $user->getKey();
    }

    public function update(User $user, OAuthClient $client): bool
    {
        return $this->view($user, $client) && $client->supportsDeveloperManagement() && $client->available();
    }

    public function regenerateSecret(User $user, OAuthClient $client): bool
    {
        return $this->update($user, $client) && in_array($client->app_type, [OAuthAppType::Web, OAuthAppType::Machine], true) && $client->confidential();
    }

    public function delete(User $user, OAuthClient $client): bool
    {
        return $this->view($user, $client) && $client->supportsDeveloperManagement();
    }

    public function publish(User $user, OAuthClient $client): bool
    {
        return $this->update($user, $client) && $client->app_type !== OAuthAppType::Machine && $client->status === OAuthClientStatus::Testing;
    }

    public function viewAny(User $user): bool
    {
        return $user->hasVerifiedEmail() && $user->is_developer;
    }

    public function introspectToken(?User $user, OAuthClient $client): bool
    {
        return $client->available() && $client->status === OAuthClientStatus::Live
            && $client->confidential() && $client->app_type === OAuthAppType::Web
            && ($client->introspection_client_ids ?? []) !== [];
    }

    public function revokeToken(?User $user, OAuthClient $client, string $authenticatedClientId): bool
    {
        return $client->getKey() === $authenticatedClientId;
    }

    public function authorize(User $user, OAuthClient $client): bool
    {
        return $client->acceptsUser($user);
    }

    public function viewLogo(User $user, OAuthClient $client): bool
    {
        return $this->authorize($user, $client) || $this->view($user, $client) || $this->administer($user, $client);
    }
}
