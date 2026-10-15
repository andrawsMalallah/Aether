<x-layout title="Approve Machine application">
    <x-ui.header />
    <main id="main-content" class="account-content">
        <x-admin.navigation />
        <a href="{{ route('admin.apps.show', $application['id']) }}">Back to application</a>
        <h1>Approve Machine application</h1>
        <h2 class="developer-application-name">{{ $application['name'] }}</h2>
        <dl class="developer-integration-settings developer-urls">
            <div><dt>Client ID</dt><dd>{{ $application['id'] }}</dd></div>
            <div><dt>Owner</dt><dd><a href="{{ route('admin.users.show', $application['owner_id']) }}">User {{ $application['owner_id'] }}</a></dd></div>
            <div><dt>Status</dt><dd>{{ $application['status'] }}</dd></div>
        </dl>
        <p class="notice">Approval activates this service and replaces its previous API permissions and resource access. All previous tokens will be revoked. Choose only the access this service needs.</p>
        @if($errors->any())
            <div class="notice notice--error" role="alert">
                <p>Review your approval.</p>
                <ul>@foreach($errors->all() as $error)<li>{{ $error }}</li>@endforeach</ul>
            </div>
        @endif
        @if($resources->isEmpty())
            <p>No eligible resource APIs are available on this page. Resources must be configured by an operator and be Live confidential Web applications.</p>
        @else
            <form method="POST" action="{{ route('admin.apps.machine.approve', $application['id']) }}" data-submit-form>
                @csrf
                <fieldset class="developer-scopes">
                    <legend>API permissions</legend>
                    @foreach($scopes as $scope => $label)
                        <label class="checkbox">
                            <input type="checkbox" name="scopes[]" value="{{ $scope }}" @checked(in_array($scope, is_array(old('scopes')) ? old('scopes') : [], true))>
                            <span>{{ $label }} (<code>{{ $scope }}</code>)</span>
                        </label>
                    @endforeach
                </fieldset>
                <fieldset class="developer-scopes developer-urls">
                    <legend>Resource APIs</legend>
                    <p>Choose the resources on this page for this approval. No resources are selected automatically.</p>
                    @foreach($resources as $resource)
                        <label class="checkbox">
                            <input type="checkbox" name="resources[]" value="{{ $resource['id'] }}" @checked(in_array($resource['id'], is_array(old('resources')) ? old('resources') : [], true))>
                            <span>{{ $resource['name'] }}<br><code>{{ $resource['id'] }}</code></span>
                        </label>
                    @endforeach
                </fieldset>
                <label class="checkbox">
                    <input type="checkbox" name="confirm" value="1" required aria-invalid="{{ $errors->has('confirm') ? 'true' : 'false' }}">
                    <span>I approve the selected API access and want to activate this Machine application.</span>
                </label>
                <x-ui.button>Approve and activate</x-ui.button>
            </form>
        @endif
        @if($resources->hasPages())
            <nav class="developer-pagination" aria-label="Resource API pages">
                @if($resources->previousPageUrl())<a href="{{ $resources->previousPageUrl() }}">Previous</a>@endif
                <span>Page {{ $resources->currentPage() }} of {{ $resources->lastPage() }}</span>
                @if($resources->nextPageUrl())<a href="{{ $resources->nextPageUrl() }}">Next</a>@endif
            </nav>
        @endif
    </main>
</x-layout>
