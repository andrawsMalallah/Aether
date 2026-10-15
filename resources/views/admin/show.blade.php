<x-layout :title="$application['name']">
    <x-ui.header />
    <main id="main-content" class="account-content">
        <x-admin.navigation />
        <a href="{{ route('admin.apps.index') }}">All applications</a>
        <h1 class="developer-application-name">{{ $application['name'] }}</h1>
        <x-ui.status />
        <dl class="developer-integration-settings developer-urls">
            <div><dt>Client ID</dt><dd>{{ $application['id'] }}</dd></div>
            <div><dt>Type</dt><dd>{{ $application['type'] }}</dd></div>
            <div><dt>Status</dt><dd>{{ $application['status'] }}</dd></div>
            <div><dt>Owner reference</dt><dd>{{ $application['owner_type'] ?? 'No owner' }} {{ $application['owner_id'] }}</dd></div>
        </dl>
        <section class="settings-section" aria-labelledby="admin-callbacks-title">
            <h2 id="admin-callbacks-title">Callback URLs</h2>
            <ul class="developer-urls">@forelse($application['redirect_uris'] as $callback)<li>{{ $callback }}</li>@empty<li>No callbacks.</li>@endforelse</ul>
        </section>
        <section class="settings-section" aria-labelledby="admin-scopes-title">
            <h2 id="admin-scopes-title">Permissions</h2>
            <ul>@forelse($application['scopes'] as $scope => $label)<li>{{ $scope }} · {{ $label }}</li>@empty<li>No permissions.</li>@endforelse</ul>
        </section>
        @if($canSuspend)
            <nav class="developer-actions" aria-label="Administrative actions"><a href="{{ route('admin.apps.suspend.confirm', $application['id']) }}">Suspend application</a></nav>
        @elseif($canRestore)
            <p class="notice">This application is suspended. Restore it to Testing to allow its owner to sign in again.</p>
            @if($application['owner_id'] === null)
                <p class="notice">No owner is assigned. Testing sign-in requires a developer owner; assign ownership separately before testing.</p>
            @endif
            <nav class="developer-actions" aria-label="Administrative actions"><a href="{{ route('admin.apps.restore.confirm', $application['id']) }}">Restore application</a></nav>
        @endif
    </main>
</x-layout>
