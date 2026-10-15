<x-layout :title="$application['name']">
    <x-ui.header />
    <main id="main-content" class="account-content">
        <a href="{{ route('developer.apps.index') }}">My applications</a>
        <h1 class="developer-application-name">{{ $application['name'] }}</h1>
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
        @if($application['status'] === 'Testing')
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
            @else
                <p class="page-description">The client secret is hidden.</p>
            @endif
            @if($canRegenerate)
                <a href="{{ route('developer.apps.secret.confirm', $application['id']) }}">Regenerate secret</a>
            @endif
        </section>
        <section class="settings-section" aria-labelledby="callbacks-title">
            <h2 id="callbacks-title">Callback URLs</h2>
            <ul class="developer-urls">@foreach($application['redirect_uris'] as $url)<li>{{ $url }}</li>@endforeach</ul>
        </section>
        <section class="settings-section" aria-labelledby="permissions-title">
            <h2 id="permissions-title">Identity permissions</h2>
            <ul>@foreach($application['scopes'] as $label)<li>{{ $label }}</li>@endforeach</ul>
        </section>
        @if($application['homepage_url'])
            <section class="settings-section" aria-labelledby="homepage-title">
                <h2 id="homepage-title">Homepage</h2>
                <p class="developer-urls">{{ $application['homepage_url'] }}</p>
            </section>
        @endif
        @if($integration !== null)
            @include('developer.integration')
        @endif
    </main>
</x-layout>
