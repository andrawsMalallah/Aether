<x-layout title="Administration">
    <x-ui.header />
    <main id="main-content" class="account-content">
        <x-admin.navigation />
        <h1>Applications</h1>
        <p class="page-description">Review registered applications and suspend access when needed.</p>
        <form method="GET" action="{{ route('admin.apps.index') }}" class="admin-application-filters">
            <x-ui.field name="search" label="Search applications" :value="$filters['search'] ?? ''" help="Part of an application name or an exact client ID." maxlength="255" />
            <div class="admin-filter-options">
                <x-ui.select name="status" label="Status" :value="$filters['status'] ?? ''" placeholder="All statuses"
                    :options="['testing' => 'Testing', 'live' => 'Live', 'suspended' => 'Suspended', 'revoked' => 'Revoked']" />
                <x-ui.select name="type" label="Application type" :value="$filters['type'] ?? ''" placeholder="All types"
                    :options="['web' => 'Web', 'spa' => 'SPA', 'mobile' => 'Mobile', 'm2m' => 'M2M']" />
            </div>
            @error('page')<p class="field__error" role="alert">{{ $message }}</p>@enderror
            <div class="developer-actions">
                <x-ui.button>Apply filters</x-ui.button>
                <a href="{{ route('admin.apps.index') }}">Clear filters</a>
            </div>
        </form>
        <ul class="developer-applications">
            @forelse($applications as $application)
                <li class="developer-application">
                    <x-ui.application-logo :name="$application['name']" :url="$application['logo_url']" />
                    <h2><a href="{{ route('admin.apps.show', $application['id']) }}">{{ $application['name'] }}</a></h2>
                    <dl class="developer-application-details">
                        <div><dt>Type</dt><dd>{{ $application['type'] }}</dd></div>
                        <div><dt>Status</dt><dd>{{ $application['status'] }}</dd></div>
                    </dl>
                </li>
            @empty
                <li>{{ array_filter($filters, fn ($value) => $value !== null && $value !== '') ? 'No applications match your filters.' : 'No applications yet.' }}</li>
            @endforelse
        </ul>
        <nav class="developer-pagination" aria-label="Application pages">
            @if($applications->previousPageUrl())<a href="{{ $applications->previousPageUrl() }}">Previous</a>@endif
            <span>Page {{ $applications->currentPage() }} of {{ $applications->lastPage() }}</span>
            @if($applications->nextPageUrl())<a href="{{ $applications->nextPageUrl() }}">Next</a>@endif
        </nav>
    </main>
</x-layout>
