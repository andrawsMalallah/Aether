<x-layout title="My applications">
    <x-ui.header />
    <main id="main-content" class="account-content">
        <h1>My applications</h1>
        <p class="page-description">Applications you own that connect to Aether.</p>
        <x-ui.status />
        <a class="button button--primary" href="{{ route('developer.apps.create') }}">Register application</a>
        @if($applications->isEmpty())
            <section class="settings-section" aria-labelledby="empty-title">
                <h2 id="empty-title">No applications yet</h2>
                <p>Your developer access is ready. Register your first application to connect it to Aether.</p>
            </section>
        @else
            <ul class="developer-applications" aria-label="Your applications">
                @foreach($applications as $application)
                    <li class="developer-application">
                        <x-ui.application-logo :name="$application['name']" :url="$application['logo_url']" />
                        <h2><a href="{{ route('developer.apps.show', $application['id']) }}">{{ $application['name'] }}</a></h2>
                        <dl class="developer-application-details">
                            <div><dt>Type</dt><dd>{{ $application['type'] }}</dd></div>
                            <div><dt>Status</dt><dd>{{ $application['status'] }}</dd></div>
                        </dl>
                    </li>
                @endforeach
            </ul>
            @if($applications->hasPages())
                <nav class="developer-pagination" aria-label="Applications pagination">
                    @if($applications->previousPageUrl())
                        <a href="{{ $applications->previousPageUrl() }}" rel="prev">Previous</a>
                    @endif
                    <span>Page {{ $applications->currentPage() }} of {{ $applications->lastPage() }}</span>
                    @if($applications->nextPageUrl())
                        <a href="{{ $applications->nextPageUrl() }}" rel="next">Next</a>
                    @endif
                </nav>
            @endif
        @endif
    </main>
</x-layout>
