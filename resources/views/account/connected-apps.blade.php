<x-layout title="Connected apps">
    <x-ui.header />
    <main id="main-content" class="account-content">
        <a href="{{ route('account.security') }}">Back to security</a>
        <h1>Connected apps</h1>
        <p class="page-description">Applications with your saved approval appear here. Authorization dates use UTC and reflect your latest approval.</p>
        <x-ui.status />
        <p class="notice">Disconnecting withdraws your saved approval and revokes your tokens and pending sign-ins for that app. You stay signed in to Aether and other apps. The application's own session may remain signed in. You can reconnect later; trusted apps may not ask for consent.</p>
        @forelse($applications as $application)
            <section class="settings-section developer-urls">
                <h2>{{ $application['name'] }}</h2>
                @if($application['unavailable'])<p class="notice">This application is unavailable. You can still withdraw your saved approval.</p>@endif
                <dl class="developer-integration-settings">
                    <div><dt>Last authorized</dt><dd><time datetime="{{ $application['datetime'] }}">{{ $application['granted_at'] }}</time></dd></div>
                    <div><dt>Permissions you approved</dt><dd><ul>@forelse($application['permissions'] as $permission)<li>{{ $permission }}</li>@empty<li>No permissions recorded.</li>@endforelse</ul></dd></div>
                </dl>
                <form method="POST" action="{{ route('account.connected-apps.disconnect', $application['id']) }}" data-submit-form>
                    @csrf
                    <label class="checkbox"><input type="checkbox" name="confirm" value="1" required><span>I want to disconnect this application.</span></label>
                    <x-ui.button variant="secondary">Disconnect app</x-ui.button>
                </form>
            </section>
        @empty
            <p>No applications have your saved approval. Apps you approve during sign-in will appear here; trusted integrations may not request consent.</p>
        @endforelse
        @if($applications->hasPages())
            <nav class="developer-pagination" aria-label="Connected app pages">
                @if($applications->previousPageUrl())<a href="{{ $applications->previousPageUrl() }}" rel="prev">Previous</a>@endif
                <span>Page {{ $applications->currentPage() }} of {{ $applications->lastPage() }}</span>
                @if($applications->nextPageUrl())<a href="{{ $applications->nextPageUrl() }}" rel="next">Next</a>@endif
            </nav>
        @endif
    </main>
</x-layout>
