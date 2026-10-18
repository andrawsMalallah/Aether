<?php

namespace App\Http\Controllers\Admin;

use App\Actions\Admin\RevokeApplicationTokens;
use App\Http\Controllers\Controller;
use App\Http\Requests\Admin\RevokeApplicationTokensRequest;
use App\Http\Resources\AdminApplicationResource;
use App\Models\OAuthClient;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Gate;

class ApplicationTokenRevocationController extends Controller
{
    public function show(OAuthClient $application): Response
    {
        Gate::authorize('revokeTokens', $application);

        return response()->view('admin.revoke-tokens', ['application' => (new AdminApplicationResource($application))->resolve()]);
    }

    public function store(RevokeApplicationTokensRequest $request, OAuthClient $application, RevokeApplicationTokens $action): RedirectResponse
    {
        $action->handle($application);

        return to_route('admin.apps.show', $application)->with('status', 'Tokens and pending sign-ins revoked. The application can still issue new credentials under its current permissions.');
    }
}
