<?php

namespace App\Http\Controllers\Account;

use App\Actions\Account\EnableDeveloper;
use App\Http\Controllers\Controller;
use App\Http\Requests\Account\EnableDeveloperRequest;
use App\Models\User;
use Illuminate\Contracts\View\View;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

class DeveloperController extends Controller
{
    public function show(Request $request): View|RedirectResponse
    {
        /** @var User $user */
        $user = $request->user();
        Gate::authorize('view', $user);
        if ($user->is_developer) {
            return to_route('developer.apps.index');
        }

        return view('developer.start');
    }

    public function enable(EnableDeveloperRequest $request, EnableDeveloper $action): RedirectResponse
    {
        /** @var User $user */
        $user = $request->user();
        $action->handle($user);

        return to_route('developer.apps.index')->with('status', 'Developer access is ready.');
    }
}
