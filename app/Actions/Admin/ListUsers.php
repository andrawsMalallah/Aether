<?php

namespace App\Actions\Admin;

use App\Models\User;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Pagination\LengthAwarePaginator;
use Illuminate\Support\Facades\Gate;

class ListUsers
{
    /**
     * @param  array{search?: string|null, role?: string|null, verification?: string|null}  $filters
     * @return LengthAwarePaginator<int, User>
     */
    public function handle(array $filters = []): LengthAwarePaginator
    {
        Gate::authorize('administerAny', User::class);
        $query = User::query()->select(['id', 'name', 'email', 'email_verified_at', 'is_admin', 'is_developer', 'created_at']);
        $search = $filters['search'] ?? '';
        if ($search !== '') {
            // Search literal text, including SQL wildcard characters.
            $pattern = '%'.str_replace(['!', '%', '_'], ['!!', '!%', '!_'], $search).'%';
            $query->where(function (Builder $query) use ($pattern): void {
                $query->whereRaw("name LIKE ? ESCAPE '!'", [$pattern])->orWhereRaw("email LIKE ? ESCAPE '!'", [$pattern]);
            });
        }
        match ($filters['role'] ?? '') {
            'admin' => $query->where('is_admin', true),
            'developer' => $query->where('is_developer', true),
            'user' => $query->where('is_admin', false)->where('is_developer', false),
            default => null,
        };
        match ($filters['verification'] ?? '') {
            'verified' => $query->whereNotNull('email_verified_at'),
            'unverified' => $query->whereNull('email_verified_at'),
            default => null,
        };

        return $query->orderBy('id')->paginate(12)
            ->appends(array_filter($filters, fn (?string $value): bool => $value !== null && $value !== ''));
    }
}
