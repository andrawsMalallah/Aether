<x-layout title="Active sessions">
    <x-ui.header />
    <main id="main-content" class="account-content">
        <a href="{{ route('account.security') }}">Back to security</a>
        <h1>Active sessions</h1>
        <p class="page-description">Review recent Aether sessions. Device and browser names are estimates, not verified identities. Activity times use UTC.</p>
        <x-ui.status />
        <p class="notice">Revoking a session signs it out on its next request. Requests already running may finish. For security, remembered sign-in is reset across your devices; other active sessions remain signed in unless selected. This does not revoke OAuth tokens or sign out of connected apps.</p>
        @forelse($sessions as $session)
            <section class="settings-section">
                <h2>{{ $session['device'] }} @if($session['current'])<span>· This session</span>@endif</h2>
                <dl class="developer-integration-settings developer-urls">
                    <div><dt>IP address</dt><dd>{{ $session['ip_address'] }}</dd></div>
                    <div><dt>Last activity</dt><dd><time datetime="{{ $session['datetime'] }}">{{ $session['last_active'] }}</time></dd></div>
                </dl>
                @unless($session['current'])
                    <form method="POST" action="{{ route('account.sessions.revoke') }}" data-submit-form>
                        @csrf
                        <input type="hidden" name="session_reference" value="{{ $session['reference'] }}">
                        <label class="checkbox"><input type="checkbox" name="confirm" value="1" required><span>I want to revoke this session.</span></label>
                        <x-ui.button variant="secondary">Revoke session</x-ui.button>
                    </form>
                @endunless
            </section>
        @empty
            <p>No recent sessions are available yet. Refresh after your next request.</p>
        @endforelse
        @if($sessions->hasPages())
            <nav class="developer-pagination" aria-label="Session pages">
                @if($sessions->previousPageUrl())<a href="{{ $sessions->previousPageUrl() }}" rel="prev">Previous</a>@endif
                <span>Page {{ $sessions->currentPage() }} of {{ $sessions->lastPage() }}</span>
                @if($sessions->nextPageUrl())<a href="{{ $sessions->nextPageUrl() }}" rel="next">Next</a>@endif
            </nav>
        @endif
        <section class="settings-section" aria-labelledby="revoke-others-title">
            <h2 id="revoke-others-title">Revoke all other sessions</h2>
            <p>Keep this session signed in and remove all other Aether sessions for your account.</p>
            <form method="POST" action="{{ route('account.sessions.revoke-others') }}" data-submit-form>
                @csrf
                <label class="checkbox"><input type="checkbox" name="confirm" value="1" required><span>I want to revoke all other sessions.</span></label>
                <x-ui.button>Revoke all other sessions</x-ui.button>
            </form>
        </section>
    </main>
</x-layout>
