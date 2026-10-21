<?php

namespace App\Http\Controllers\Account;

use App\Actions\Account\ListAccountExports;
use App\Actions\Account\RequestAccountExport;
use App\Http\Controllers\Controller;
use App\Http\Requests\Account\ListAccountExportsRequest;
use App\Http\Requests\Account\RequestAccountExportRequest;
use App\Http\Resources\AccountExportResource;
use App\Models\AccountExport;
use App\Services\PrivateStorage;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Gate;
use Symfony\Component\HttpFoundation\StreamedResponse;

class AccountExportController extends Controller
{
    public function index(ListAccountExportsRequest $request, ListAccountExports $action): Response
    {
        $exports = $action->handle($request->user());
        $exports->through(fn (AccountExport $export): array => (new AccountExportResource($export))->resolve($request));

        return response()->view('account.export', compact('exports'))->header('Cache-Control', 'no-store, private');
    }

    public function store(RequestAccountExportRequest $request, RequestAccountExport $action): RedirectResponse
    {
        $action->handle($request->user());

        return to_route('account.export.index')->with('status', 'Your export was requested. We will email you when it is ready.')
            ->header('Cache-Control', 'no-store, private');
    }

    public function download(Request $request, AccountExport $accountExport): StreamedResponse
    {
        Gate::authorize('download', $accountExport);
        abort_unless($accountExport->available() && PrivateStorage::disk()->exists($accountExport->relativePath()), 404);

        return PrivateStorage::response($accountExport->relativePath(), 'application/json', [
            'Content-Type' => 'application/json', 'Cache-Control' => 'no-store, private',
            'X-Content-Type-Options' => 'nosniff', 'Referrer-Policy' => 'no-referrer',
        ], 'aether-account-export.json');
    }
}
