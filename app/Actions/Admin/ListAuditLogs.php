<?php

namespace App\Actions\Admin;

use App\Models\AuditLog;
use Carbon\CarbonImmutable;
use Illuminate\Pagination\LengthAwarePaginator;
use Illuminate\Support\Facades\Gate;

class ListAuditLogs
{
    /**
     * @param  array{event?: string|null, client_id?: string|null, actor?: string|null, from?: string|null, to?: string|null}  $filters
     * @return LengthAwarePaginator<int, AuditLog>
     */
    public function handle(array $filters = []): LengthAwarePaginator
    {
        Gate::authorize('viewAny', AuditLog::class);
        $query = AuditLog::query()->select(['id', 'user_id', 'client_id', 'event', 'created_at'])
            ->with(['actor:id,name,email', 'client:id,name']);
        foreach (['event', 'client_id'] as $field) {
            if (! empty($filters[$field])) {
                $query->where($field, $filters[$field]);
            }
        }
        $actor = $filters['actor'] ?? '';
        if ($actor !== '') {
            if (ctype_digit($actor)) {
                $query->where('user_id', $actor);
            } else {
                $query->whereHas('actor', fn ($query) => $query->where('email', $actor));
            }
        }
        // UTC day boundaries keep the timestamp index usable and include the entire end date.
        if (! empty($filters['from'])) {
            $query->where('created_at', '>=', CarbonImmutable::parse($filters['from'].' 00:00:00', 'UTC'));
        }
        if (! empty($filters['to'])) {
            $query->where('created_at', '<', CarbonImmutable::parse($filters['to'].' 00:00:00', 'UTC')->addDay());
        }

        return $query->orderByDesc('created_at')->orderByDesc('id')->paginate(12)
            ->appends(array_filter($filters, fn (?string $value): bool => $value !== null && $value !== ''));
    }
}
