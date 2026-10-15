<?php

namespace App\Http\Controllers\Developer;

use App\Actions\Developer\ListApplications;
use App\Actions\Developer\RegisterApplication;
use App\Actions\Developer\UpdateApplication;
use App\Http\Controllers\Controller;
use App\Http\Requests\Developer\RegisterApplicationRequest;
use App\Http\Requests\Developer\UpdateApplicationRequest;
use App\Http\Resources\DeveloperApplicationDetailResource;
use App\Http\Resources\DeveloperApplicationResource;
use App\Models\OAuthClient;
use App\Models\User;
use App\Services\OAuth\OidcMetadata;
use Illuminate\Contracts\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Hash;

class ApplicationController extends Controller
{
    public function create(): Response
    {
        Gate::authorize('create', OAuthClient::class);

        return response()->view('developer.create', ['scopes' => array_intersect_key(config('oauth.scopes'), array_flip(['openid', 'profile', 'email']))])
            ->header('Cache-Control', 'private, no-store');
    }

    public function store(RegisterApplicationRequest $request, RegisterApplication $action): RedirectResponse
    {
        /** @var User $user */
        $user = $request->user();
        $client = $action->handle($user, $request->validated());
        // Only an encrypted, app-bound one-time handoff enters session storage.
        if ($client->confidential()) {
            $request->session()->flash('developer.credentials.'.$client->id, Crypt::encryptString($client->plainSecret));
        }

        return to_route('developer.apps.show', $client)->with('status', 'Your application has been registered.')
            ->header('Cache-Control', 'private, no-store');
    }

    public function createMachine(): Response
    {
        Gate::authorize('create', OAuthClient::class);

        return response()->view('developer.create', ['scopes' => [], 'machine' => true])
            ->header('Cache-Control', 'private, no-store');
    }

    public function show(Request $request, OAuthClient $application, OidcMetadata $metadata): Response
    {
        Gate::authorize('view', $application);
        $encryptedSecret = $request->session()->pull('developer.credentials.'.$application->id);
        $clientSecret = $application->confidential() && is_string($encryptedSecret) ? Crypt::decryptString($encryptedSecret) : null;

        return response()->view('developer.show', [
            'application' => (new DeveloperApplicationDetailResource($application))->resolve($request),
            // A stale handoff from another browser session must not show an obsolete secret.
            'clientSecret' => $clientSecret !== null && Hash::check($clientSecret, $application->secret) ? $clientSecret : null,
            'canUpdate' => Gate::allows('update', $application),
            'canRegenerate' => Gate::allows('regenerateSecret', $application),
            'canPublish' => Gate::allows('publish', $application),
            'canDelete' => Gate::allows('delete', $application),
            'integration' => $application->supportsDeveloperManagement() ? $metadata->discovery() : null,
        ])->header('Cache-Control', 'private, no-store');
    }

    public function edit(Request $request, OAuthClient $application): Response
    {
        Gate::authorize('update', $application);

        return response()->view('developer.edit', [
            'application' => (new DeveloperApplicationDetailResource($application))->resolve($request),
            'scopes' => array_intersect_key(config('oauth.scopes'), array_flip(['openid', 'profile', 'email'])),
        ])->header('Cache-Control', 'private, no-store');
    }

    public function update(UpdateApplicationRequest $request, OAuthClient $application, UpdateApplication $action): RedirectResponse
    {
        $action->handle($application, $request->validated());

        return to_route('developer.apps.show', $application)->with('status', 'Your application settings have been saved.');
    }

    public function index(Request $request, ListApplications $action): View
    {
        Gate::authorize('viewAny', OAuthClient::class);
        /** @var User $user */
        $user = $request->user();
        $applications = $action->handle($user);
        $applications->through(fn (OAuthClient $client): array => (new DeveloperApplicationResource($client))->resolve($request));

        return view('developer.index', ['applications' => $applications]);
    }
}
