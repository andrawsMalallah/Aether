<?php

namespace App\Actions\Admin;

use App\Models\OAuthClient;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Pagination\LengthAwarePaginator;
use Illuminate\Support\Facades\Gate;

class ListApplications
{
    /**
     * @param  array{search?: string|null, status?: string|null, type?: string|null}  $filters
     * @return LengthAwarePaginator<int, OAuthClient>
     */
    public function handle(array $filters = []): LengthAwarePaginator
    {
        Gate::authorize('administerAny', OAuthClient::class);

        $query = OAuthClient::query()->select(['id', 'name', 'logo_path', 'app_type', 'status', 'revoked']);
        $search = $filters['search'] ?? '';
        if ($search !== '') {
            // Treat SQL wildcard characters literally; client IDs match exactly.
            $pattern = '%'.str_replace(['!', '%', '_'], ['!!', '!%', '!_'], $search).'%';
            $query->where(function (Builder $query) use ($search, $pattern): void {
                $query->whereRaw("name LIKE ? ESCAPE '!'", [$pattern])->orWhere('id', $search);
            });
        }
        $status = $filters['status'] ?? null;
        if ($status === 'revoked') {
            $query->where('revoked', true);
        } elseif ($status !== null && $status !== '') {
            $query->where('revoked', false)->where('status', $status);
        }
        if (! empty($filters['type'])) {
            $query->where('app_type', $filters['type']);
        }

        return $query->orderBy('id')->paginate(12)->appends(array_filter($filters, fn (?string $value): bool => $value !== null && $value !== ''));
    }
}
