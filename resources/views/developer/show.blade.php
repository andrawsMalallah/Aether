<x-layout :title="$application['name']">
    <x-ui.header />
    <main id="main-content" class="account-content">
        <a href="{{ route('developer.apps.index') }}">My applications</a>
        <h1 class="developer-application-name">{{ $application['name'] }}</h1>
        <x-ui.application-logo :name="$application['name']" :url="$application['logo_url']" />
        <x-ui.status />
        @if($canUpdate || $canPublish)
            <nav class="developer-actions" aria-label="Application actions">
                @if($canUpdate)<a href="{{ route('developer.apps.edit', $application['id']) }}">Edit settings</a>@endif
                @if($canPublish)<a href="{{ route('developer.apps.publish.confirm', $application['id']) }}">Go live</a>@endif
            </nav>
        @endif
        <dl class="developer-application-details">
            <div><dt>Type</dt><dd>{{ $application['type'] }}</dd></div>
            <div><dt>Status</dt><dd>{{ $application['status'] }}</dd></div>
        </dl>
        @if($application['machine'])
            <p class="notice">API permissions and activation are managed by an administrator. Contact the Aether operator with your client ID. Testing, Suspended and Revoked machine applications cannot obtain tokens.</p>
        @elseif($application['status'] === 'Testing')
            <p class="page-description">Only you can sign in through this application while it is in Testing.</p>
        @endif
        <section class="settings-section" aria-labelledby="credentials-title">
            <h2 id="credentials-title">Credentials</h2>
            <x-ui.field name="client_id" label="Client ID" :value="$application['id']" readonly autocomplete="off" />
            @if($clientSecret !== null)
                <p class="notice" role="status">Save your client secret now. It will not be shown again. Keep it in your application's server environment.</p>
                <div class="field">
                    <label for="client-secret">Client secret</label>
                    <input id="client-secret" type="text" value="{{ $clientSecret }}" readonly autocomplete="off" spellcheck="false">
                </div>
            @elseif($application['confidential'])
                <p class="page-description">The client secret is hidden.</p>
            @else
                <p class="page-description">This is a public client. No client secret is issued. Use authorization code flow with PKCE (S256).</p>
            @endif
            @if($canRegenerate)
                <a href="{{ route('developer.apps.secret.confirm', $application['id']) }}">Regenerate secret</a>
            @endif
        </section>
        @if(!$application['machine'])
        <section class="settings-section" aria-labelledby="callbacks-title">
            <h2 id="callbacks-title">Callback URLs</h2>
            <ul class="developer-urls">@foreach($application['redirect_uris'] as $url)<li>{{ $url }}</li>@endforeach</ul>
        </section>
        @endif
        <section class="settings-section" aria-labelledby="permissions-title">
            <h2 id="permissions-title">{{ $application['machine'] ? 'Approved API permissions' : 'Identity permissions' }}</h2>
            <ul>@forelse($application['scopes'] as $scope => $label)<li>{{ $label }}@if($application['machine']) (<code>{{ $scope }}</code>)@endif</li>@empty<li>No permissions approved.</li>@endforelse</ul>
        </section>
        @if($application['homepage_url'])
            <section class="settings-section" aria-labelledby="homepage-title">
                <h2 id="homepage-title">Homepage</h2>
                <p class="developer-urls">{{ $application['homepage_url'] }}</p>
            </section>
        @endif
        @if($integration !== null)
            @include($application['machine'] ? 'developer.machine-integration' : ($application['mobile'] ? 'developer.mobile-integration' : 'developer.integration'))
        @endif
        @if($canDelete)
            <section class="settings-section" aria-labelledby="delete-application-title">
                <h2 id="delete-application-title">Delete application</h2>
                <p class="page-description">Permanently stop this application's access to Aether. This cannot be undone.</p>
                <a href="{{ route('developer.apps.delete.confirm', $application['id']) }}">Delete application</a>
            </section>
        @endif
    </main>
</x-layout>
