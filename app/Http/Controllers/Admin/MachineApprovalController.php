<?php

namespace App\Http\Controllers\Admin;

use App\Actions\Admin\ApproveMachineApplication;
use App\Actions\Admin\ListMachineResources;
use App\Http\Controllers\Controller;
use App\Http\Requests\Admin\ApproveMachineApplicationRequest;
use App\Http\Resources\AdminApplicationResource;
use App\Http\Resources\DeveloperApplicationResource;
use App\Models\OAuthClient;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Response;

class MachineApprovalController extends Controller
{
    public function show(ApproveMachineApplicationRequest $request, OAuthClient $application, ListMachineResources $list): Response
    {
        $resources = $list->handle($application);
        $resources->through(fn (OAuthClient $resource): array => (new DeveloperApplicationResource($resource))->resolve($request));

        return response()->view('admin.approve-machine', [
            'application' => (new AdminApplicationResource($application))->resolve($request),
            'resources' => $resources,
            'scopes' => array_intersect_key(config('oauth.scopes'), array_flip(config('oauth.machine_scopes'))),
        ])->header('Cache-Control', 'private, no-store');
    }

    public function store(ApproveMachineApplicationRequest $request, OAuthClient $application, ApproveMachineApplication $approve): RedirectResponse
    {
        $approve->handle($application, $request->validated());

        return to_route('admin.apps.show', $application)->with('status', 'Machine application approved and activated. Previous tokens remain invalid.')
            ->header('Cache-Control', 'private, no-store');
    }
}
