<?php

namespace App\Http\Controllers\Admin;

use App\Actions\Admin\ListUsers;
use App\Http\Controllers\Controller;
use App\Http\Requests\Admin\ListUsersRequest;
use App\Http\Resources\AdminUserResource;
use App\Http\Resources\DeveloperApplicationResource;
use App\Models\OAuthClient;
use App\Models\User;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Gate;

class UserController extends Controller
{
    public function index(ListUsersRequest $request, ListUsers $action): Response
    {
        Gate::authorize('administerAny', User::class);
        $filters = $request->safe()->only(['search', 'role', 'verification']);
        $users = $action->handle($filters);
        $users->through(fn (User $user): array => (new AdminUserResource($user))->resolve($request));

        return response()->view('admin.users.index', compact('users', 'filters'));
    }

    public function show(ListUsersRequest $request, User $user): Response
    {
        Gate::authorize('administer', $user);
        Gate::authorize('administerAny', OAuthClient::class);
        $applications = OAuthClient::query()->select(['id', 'name', 'app_type', 'status', 'revoked'])
            ->where('owner_type', $user->getMorphClass())->where('owner_id', $user->getKey())
            ->orderBy('id')->paginate(12);
        $applications->through(fn (OAuthClient $client): array => (new DeveloperApplicationResource($client))->resolve($request));

        return response()->view('admin.users.show', [
            'user' => (new AdminUserResource($user))->resolve($request),
            'twoFactorEnabled' => $user->hasEnabledTwoFactorAuthentication(),
            'applications' => $applications,
        ]);
    }
}
