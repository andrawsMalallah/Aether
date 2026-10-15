<x-layout :title="$user['name']">
    <x-ui.header />
    <main id="main-content" class="account-content">
        <x-admin.navigation />
        <a href="{{ route('admin.users.index') }}">All users</a>
        <h1 class="developer-application-name">{{ $user['name'] }}</h1>
        <dl class="developer-integration-settings developer-urls">
            <div><dt>User ID</dt><dd>{{ $user['id'] }}</dd></div>
            <div><dt>Email</dt><dd>{{ $user['email'] }}</dd></div>
            <div><dt>Email verification</dt><dd>{{ $user['verified'] ? 'Verified' : 'Unverified' }}</dd></div>
            <div><dt>Roles</dt><dd>{{ implode(', ', $user['roles']) }}</dd></div>
            <div><dt>Two-factor authentication</dt><dd>{{ $twoFactorEnabled ? 'Enabled and confirmed' : 'Not confirmed' }}</dd></div>
            <div><dt>Joined (UTC)</dt><dd>{{ $user['joined_at'] ?? 'Not recorded' }}</dd></div>
        </dl>
        <p><a href="{{ route('admin.audit.index', ['actor' => $user['id']]) }}">View recorded events for this user</a></p>
        <p class="page-description">Events include existing user references; credential replay events may identify the credential owner rather than the requester.</p>
        <section class="settings-section" aria-labelledby="owned-applications-title">
            <h2 id="owned-applications-title">Owned applications</h2>
            <ul class="developer-applications">
                @forelse($applications as $application)
                    <li class="developer-application">
                        <h3 class="developer-application-name"><a href="{{ route('admin.apps.show', $application['id']) }}">{{ $application['name'] }}</a></h3>
                        <p>{{ $application['type'] }} · {{ $application['status'] }}</p>
                    </li>
                @empty
                    <li>No owned applications.</li>
                @endforelse
            </ul>
            <nav class="developer-pagination" aria-label="Owned application pages">
                @if($applications->previousPageUrl())<a href="{{ $applications->previousPageUrl() }}">Previous</a>@endif
                <span>Page {{ $applications->currentPage() }} of {{ $applications->lastPage() }}</span>
                @if($applications->nextPageUrl())<a href="{{ $applications->nextPageUrl() }}">Next</a>@endif
            </nav>
        </section>
    </main>
</x-layout>
