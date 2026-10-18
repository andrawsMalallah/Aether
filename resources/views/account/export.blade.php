<x-layout title="Export account data">
    <x-ui.header />
    <main id="main-content" class="account-content">
        <a href="{{ route('account.security') }}">Back to security</a>
        <h1>Export account data</h1>
        <p class="page-description">Download your Aether data as a JSON file. We prepare it in the background and email you when it is ready.</p>
        <x-ui.status />
        <section class="settings-section" aria-labelledby="export-contents-title">
            <h2 id="export-contents-title">What is included</h2>
            <p>Your profile and settings, saved application approvals including withdrawn approvals, owned application settings, recent session metadata when available, and your audit history.</p>
            <p>Passwords, tokens, recovery codes, session identifiers and image files are excluded. The file contains personal information; keep it somewhere private.</p>
            <form method="POST" action="{{ route('account.export.store') }}" data-submit-form>
                @csrf
                <label class="checkbox"><input type="checkbox" name="confirm" value="1" required><span>I want to prepare a private copy of my account data.</span></label>
                @error('confirm')<p class="field__error" role="alert">{{ $message }}</p>@enderror
                <p class="page-description">You can request one export per hour. Each completed file is available for 24 hours.</p>
                <x-ui.button>Request export</x-ui.button>
            </form>
        </section>
        <h2>Recent requests</h2>
        @error('page')<p class="field__error" role="alert">{{ $message }}</p>@enderror
        @forelse($exports as $export)
            <section class="settings-section developer-urls">
                <h3>Requested {{ $export['requested_at'] }}</h3>
                @if($export['available'])
                    <p>Ready. Available until {{ $export['expires_at'] }}.</p>
                    <a href="{{ route('account.export.download', $export['id']) }}">Download JSON</a>
                @elseif($export['status'] === 'pending')
                    <p role="status">Being prepared. Refresh this page or wait for the email.</p>
                @elseif($export['status'] === 'failed')
                    <p>We could not prepare this export. You can request another after the one-hour waiting period.</p>
                @else
                    <p>Expired. This export is no longer available.</p>
                @endif
            </section>
        @empty
            <p>No exports requested yet.</p>
        @endforelse
        @if($exports->hasPages())
            <nav class="developer-pagination" aria-label="Account export pages">
                @if($exports->previousPageUrl())<a href="{{ $exports->previousPageUrl() }}" rel="prev">Previous</a>@endif
                <span>Page {{ $exports->currentPage() }} of {{ $exports->lastPage() }}</span>
                @if($exports->nextPageUrl())<a href="{{ $exports->nextPageUrl() }}" rel="next">Next</a>@endif
            </nav>
        @endif
    </main>
</x-layout>
