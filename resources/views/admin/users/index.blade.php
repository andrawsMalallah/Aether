<x-layout title="Users">
    <x-ui.header />
    <main id="main-content" class="account-content">
        <x-admin.navigation />
        <h1>Users</h1>
        <p class="page-description">Review accounts and their registered applications.</p>
        <form method="GET" action="{{ route('admin.users.index') }}" class="admin-application-filters">
            <x-ui.field name="search" label="Search users" :value="$filters['search'] ?? ''" help="Part of a name or email address." maxlength="255" />
            <div class="admin-filter-options">
                <x-ui.select name="role" label="Role" :value="$filters['role'] ?? ''" placeholder="All roles" :options="['admin' => 'Administrator', 'developer' => 'Developer', 'user' => 'User (neither role)']" />
                <x-ui.select name="verification" label="Email verification" :value="$filters['verification'] ?? ''" placeholder="All accounts" :options="['verified' => 'Verified', 'unverified' => 'Unverified']" />
            </div>
            @error('page')<p class="field__error" role="alert">{{ $message }}</p>@enderror
            <div class="developer-actions"><x-ui.button>Apply filters</x-ui.button><a href="{{ route('admin.users.index') }}">Clear filters</a></div>
        </form>
        <ul class="developer-applications">
            @forelse($users as $user)
                <li class="developer-application">
                    <h2 class="developer-application-name"><a href="{{ route('admin.users.show', $user['id']) }}">{{ $user['name'] }}</a></h2>
                    <dl class="developer-application-details developer-urls">
                        <div><dt>Email</dt><dd>{{ $user['email'] }}</dd></div>
                        <div><dt>Roles</dt><dd>{{ implode(', ', $user['roles']) }}</dd></div>
                        <div><dt>Email verification</dt><dd>{{ $user['verified'] ? 'Verified' : 'Unverified' }}</dd></div>
                    </dl>
                </li>
            @empty
                <li>No users match your filters.</li>
            @endforelse
        </ul>
        <nav class="developer-pagination" aria-label="User pages">
            @if($users->previousPageUrl())<a href="{{ $users->previousPageUrl() }}">Previous</a>@endif
            <span>Page {{ $users->currentPage() }} of {{ $users->lastPage() }}</span>
            @if($users->nextPageUrl())<a href="{{ $users->nextPageUrl() }}">Next</a>@endif
        </nav>
    </main>
</x-layout>
