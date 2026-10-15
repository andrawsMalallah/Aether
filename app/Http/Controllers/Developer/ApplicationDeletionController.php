<?php

namespace App\Http\Controllers\Developer;

use App\Actions\Developer\DeleteApplication;
use App\Enums\OAuthAppType;
use App\Http\Controllers\Controller;
use App\Http\Requests\Developer\DeleteApplicationRequest;
use App\Http\Resources\DeveloperApplicationDetailResource;
use App\Models\OAuthClient;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Gate;

class ApplicationDeletionController extends Controller
{
    public function confirm(OAuthClient $application): Response
    {
        Gate::authorize('delete', $application);

        return response()->view('developer.confirm-change', [
            'application' => (new DeveloperApplicationDetailResource($application))->resolve(),
            'title' => 'Delete application',
            'description' => $application->app_type === OAuthAppType::Machine
                ? 'Token issuance will stop permanently and all access tokens for this service will be invalidated. Its record and audit history will be retained for administration. This cannot be undone.'
                : 'Sign-in and token issuance will stop permanently. All access tokens, refresh tokens and pending sign-ins for this app will be invalidated. Existing sessions in your app may remain signed in. Its record and audit history will be retained for administration. This cannot be undone.',
            'confirmation' => 'I understand that this application will be permanently deleted and cannot be restored.',
            'button' => 'Delete application',
            'action' => route('developer.apps.delete.store', $application),
        ])->header('Cache-Control', 'private, no-store');
    }

    public function store(DeleteApplicationRequest $request, OAuthClient $application, DeleteApplication $action): RedirectResponse
    {
        $action->handle($application);
        $request->session()->forget('developer.credentials.'.$application->id);

        return to_route('developer.apps.index')->with('status', 'Your application has been deleted. Its tokens and pending sign-ins have been revoked.')
            ->header('Cache-Control', 'private, no-store');
    }
}
