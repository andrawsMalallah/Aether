<?php

namespace App\Http\Controllers\Developer;

use App\Actions\Developer\RegenerateApplicationSecret;
use App\Http\Controllers\Controller;
use App\Http\Requests\Developer\RegenerateApplicationSecretRequest;
use App\Http\Resources\DeveloperApplicationDetailResource;
use App\Models\OAuthClient;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Gate;

class ApplicationCredentialsController extends Controller
{
    public function confirm(OAuthClient $application): Response
    {
        Gate::authorize('regenerateSecret', $application);

        return response()->view('developer.confirm-change', [
            'application' => (new DeveloperApplicationDetailResource($application))->resolve(),
            'title' => 'Regenerate client secret',
            'description' => 'The old secret stops working immediately. All access tokens, refresh tokens and pending sign-ins for this app will be invalidated. Existing sessions in your app may remain signed in.',
            'confirmation' => 'I am ready to update my application with the new secret.',
            'button' => 'Regenerate secret',
            'action' => route('developer.apps.secret.store', $application),
        ])->header('Cache-Control', 'private, no-store');
    }

    public function store(RegenerateApplicationSecretRequest $request, OAuthClient $application, RegenerateApplicationSecret $action): RedirectResponse
    {
        $client = $action->handle($application);
        $request->session()->flash('developer.credentials.'.$client->id, Crypt::encryptString($client->plainSecret));

        return to_route('developer.apps.show', $client)->with('status', 'Your client secret has been regenerated. Existing tokens have been revoked.')
            ->header('Cache-Control', 'private, no-store');
    }
}
