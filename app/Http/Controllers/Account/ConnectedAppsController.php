<?php

namespace App\Http\Controllers\Account;

use App\Actions\Account\DisconnectApp;
use App\Actions\Account\ListConnectedApps;
use App\Http\Controllers\Controller;
use App\Http\Requests\Account\DisconnectAppRequest;
use App\Http\Requests\Account\ListConnectedAppsRequest;
use App\Http\Resources\ConnectedAppResource;
use App\Models\Consent;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Response;

class ConnectedAppsController extends Controller
{
    public function index(ListConnectedAppsRequest $request, ListConnectedApps $action): Response
    {
        $applications = $action->handle($request->user());
        $applications->through(fn (Consent $consent): array => (new ConnectedAppResource($consent))->resolve($request));

        return response()->view('account.connected-apps', compact('applications'))->header('Cache-Control', 'no-store, private');
    }

    public function disconnect(DisconnectAppRequest $request, Consent $consent, DisconnectApp $action): RedirectResponse
    {
        $action->handle($request->user(), $consent);

        return to_route('account.connected-apps.index')->with('status', 'Application disconnected. Your tokens and pending sign-ins for this app were revoked. Its own session may remain signed in.')->header('Cache-Control', 'no-store, private');
    }
}
