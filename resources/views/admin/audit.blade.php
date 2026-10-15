<x-layout title="Audit log">
    <x-ui.header />
    <main id="main-content" class="account-content">
        <x-admin.navigation />
        <h1>Audit log</h1>
        <p class="page-description">Recorded application and OAuth events. All times and date filters use UTC. Names reflect current records; deleted records retain their IDs.</p>
        <p class="page-description">For replay and token-revocation events, the user reference identifies the credential owner, not necessarily the person who sent the request.</p>
        <form method="GET" action="{{ route('admin.audit.index') }}">
            <x-ui.select name="event" label="Action" :options="$events" :value="$filters['event'] ?? ''" placeholder="All actions" />
            <x-ui.field name="client_id" label="Application client ID" :value="$filters['client_id'] ?? ''" maxlength="36" />
            <x-ui.field name="actor" label="Actor" :value="$filters['actor'] ?? ''" help="Exact email address or user ID." maxlength="255" />
            <div class="admin-filter-options">
                <x-ui.field name="from" label="From date (UTC)" type="date" :value="$filters['from'] ?? ''" />
                <x-ui.field name="to" label="Through date (UTC)" type="date" :value="$filters['to'] ?? ''" />
            </div>
            @error('page')<p class="field__error" role="alert">{{ $message }}</p>@enderror
            <div class="developer-actions"><x-ui.button>Apply filters</x-ui.button><a href="{{ route('admin.audit.index') }}">Clear filters</a></div>
        </form>
        <ol class="developer-applications">
            @forelse($logs as $log)
                <li class="developer-application developer-urls">
                    <h2>{{ $log['event'] }}</h2>
                    <p><time datetime="{{ $log['datetime'] }}">{{ $log['time'] }} UTC</time> · Event #{{ $log['id'] }}</p>
                    <dl class="developer-integration-settings">
                        <div><dt>Actor</dt><dd>
                            @if($log['actor_name'] !== null){{ $log['actor_name'] }} · {{ $log['actor_email'] }} (ID {{ $log['actor_id'] }})
                            @elseif($log['actor_id'] !== null)Unavailable user (ID {{ $log['actor_id'] }})
                            @else>No user recorded @endif
                        </dd></div>
                        <div><dt>Application</dt><dd>
                            @if($log['client_exists'])<a href="{{ route('admin.apps.show', $log['client_id']) }}">{{ $log['client_name'] }}</a> · {{ $log['client_id'] }}
                            @elseif($log['client_id'] !== null)Unavailable application · {{ $log['client_id'] }}
                            @else>No application recorded @endif
                        </dd></div>
                    </dl>
                </li>
            @empty
                <li>{{ array_filter($filters, fn ($value) => $value !== null && $value !== '') ? 'No events match your filters.' : 'No recorded events yet.' }}</li>
            @endforelse
        </ol>
        <nav class="developer-pagination" aria-label="Audit log pages">
            @if($logs->previousPageUrl())<a href="{{ $logs->previousPageUrl() }}">Previous</a>@endif
            <span>Page {{ $logs->currentPage() }} of {{ $logs->lastPage() }}</span>
            @if($logs->nextPageUrl())<a href="{{ $logs->nextPageUrl() }}">Next</a>@endif
        </nav>
    </main>
</x-layout>
