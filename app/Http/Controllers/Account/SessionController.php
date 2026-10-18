<?php

namespace App\Http\Controllers\Account;

use App\Actions\Account\ListSessions;
use App\Actions\Account\RevokeSessions;
use App\Http\Controllers\Controller;
use App\Http\Requests\Account\ListSessionsRequest;
use App\Http\Requests\Account\RevokeSessionsRequest;
use App\Http\Resources\AccountSessionResource;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Response;

class SessionController extends Controller
{
    public function index(ListSessionsRequest $request, ListSessions $action): Response
    {
        $sessions = $action->handle($request->user(), $request->session()->getId());
        $sessions->through(fn (\stdClass $session): array => (new AccountSessionResource($session))->resolve($request));

        return response()->view('account.sessions', compact('sessions'))->header('Cache-Control', 'no-store, private');
    }

    public function revoke(RevokeSessionsRequest $request, RevokeSessions $action): RedirectResponse
    {
        $action->handle($request->user(), $request->session()->getId(), $request->validated('session_reference'));

        return to_route('account.sessions.index')->with('status', 'Session revoked. Remembered sign-in has been reset across your devices.')->header('Cache-Control', 'no-store, private');
    }

    public function revokeOthers(RevokeSessionsRequest $request, RevokeSessions $action): RedirectResponse
    {
        $action->handle($request->user(), $request->session()->getId(), null);

        return to_route('account.sessions.index')->with('status', 'Other sessions revoked. This session stays signed in. Remembered sign-in has been reset across your devices.')->header('Cache-Control', 'no-store, private');
    }
}
