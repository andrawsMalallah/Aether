<?php

namespace App\Http\Controllers\Admin;

use App\Actions\Admin\ListAuditLogs;
use App\Enums\OAuthAuditEvent;
use App\Http\Controllers\Controller;
use App\Http\Requests\Admin\ListAuditLogsRequest;
use App\Http\Resources\AdminAuditLogResource;
use App\Models\AuditLog;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Gate;

class AuditLogController extends Controller
{
    public function index(ListAuditLogsRequest $request, ListAuditLogs $action): Response
    {
        Gate::authorize('viewAny', AuditLog::class);
        $filters = $request->safe()->only(['event', 'client_id', 'actor', 'from', 'to']);
        $logs = $action->handle($filters);
        $logs->through(fn (AuditLog $log): array => (new AdminAuditLogResource($log))->resolve($request));
        $events = [];
        foreach (OAuthAuditEvent::cases() as $event) {
            $events[$event->value] = $event->value;
        }

        return response()->view('admin.audit', compact('logs', 'filters', 'events'));
    }
}
