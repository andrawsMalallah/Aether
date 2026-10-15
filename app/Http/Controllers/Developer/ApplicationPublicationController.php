<?php

namespace App\Http\Controllers\Developer;

use App\Actions\Developer\PublishApplication;
use App\Http\Controllers\Controller;
use App\Http\Requests\Developer\PublishApplicationRequest;
use App\Http\Resources\DeveloperApplicationDetailResource;
use App\Models\OAuthClient;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Gate;

class ApplicationPublicationController extends Controller
{
    public function confirm(OAuthClient $application): Response
    {
        Gate::authorize('publish', $application);

        return response()->view('developer.confirm-change', [
            'application' => (new DeveloperApplicationDetailResource($application))->resolve(),
            'title' => 'Go live',
            'description' => 'Any verified Aether user will be able to sign in through this application. Make sure your callback URLs and identity permissions are ready.',
            'confirmation' => 'My application is ready for other people to sign in.',
            'button' => 'Go live',
            'action' => route('developer.apps.publish.store', $application),
        ])->header('Cache-Control', 'private, no-store');
    }

    public function store(PublishApplicationRequest $request, OAuthClient $application, PublishApplication $action): RedirectResponse
    {
        $action->handle($application);

        return to_route('developer.apps.show', $application)->with('status', 'Your application is live. Verified Aether users can now sign in.');
    }
}
