<?php

namespace App\Http\Controllers\Admin;

use App\Actions\Admin\ListApplications;
use App\Actions\Admin\RestoreApplication;
use App\Actions\Admin\SuspendApplication;
use App\Http\Controllers\Controller;
use App\Http\Requests\Admin\ListApplicationsRequest;
use App\Http\Requests\Admin\RestoreApplicationRequest;
use App\Http\Requests\Admin\SuspendApplicationRequest;
use App\Http\Resources\AdminApplicationResource;
use App\Http\Resources\DeveloperApplicationResource;
use App\Models\OAuthClient;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Gate;

class ApplicationController extends Controller
{
    public function index(ListApplicationsRequest $request, ListApplications $action): Response
    {
        Gate::authorize('administerAny', OAuthClient::class);
        $filters = $request->safe()->only(['search', 'status', 'type']);
        $applications = $action->handle($filters);
        $applications->through(fn (OAuthClient $client): array => (new DeveloperApplicationResource($client))->resolve($request));

        return response()->view('admin.index', compact('applications', 'filters'));
    }

    public function show(OAuthClient $application): Response
    {
        Gate::authorize('administer', $application);

        return response()->view('admin.show', [
            'application' => (new AdminApplicationResource($application))->resolve(),
            'canSuspend' => Gate::allows('suspend', $application),
            'canRevokeTokens' => Gate::allows('revokeTokens', $application),
            'canRestore' => Gate::allows('restore', $application),
            'canApproveMachine' => Gate::allows('approveMachine', $application),
        ]);
    }

    public function confirm(OAuthClient $application): Response
    {
        Gate::authorize('suspend', $application);

        return response()->view('admin.suspend', ['application' => (new AdminApplicationResource($application))->resolve()]);
    }

    public function suspend(SuspendApplicationRequest $request, OAuthClient $application, SuspendApplication $action): RedirectResponse
    {
        $action->handle($application);

        return to_route('admin.apps.show', $application)->with('status', 'Application suspended. Its tokens and pending sign-ins have been revoked.');
    }

    public function confirmRestore(OAuthClient $application): Response
    {
        Gate::authorize('restore', $application);

        return response()->view('admin.restore', ['application' => (new AdminApplicationResource($application))->resolve()]);
    }

    public function restore(RestoreApplicationRequest $request, OAuthClient $application, RestoreApplication $action): RedirectResponse
    {
        $action->handle($application);

        return to_route('admin.apps.show', $application)->with('status', 'Application restored to Testing. Previous tokens and pending sign-ins remain invalid.');
    }
}
