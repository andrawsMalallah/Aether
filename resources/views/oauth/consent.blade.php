<x-ui.auth-card title="Continue to {{ $client->name }}" description="Choose whether to share your Aether account details with this application.">
    <p class="notice">Signed in as {{ $user->email }}</p>
    @if($client->logo_path)
        <img class="consent-logo" src="{{ route('passport.client.logo', $client) }}" alt="{{ $client->name }} logo" width="48" height="48">
    @endif
    <h2>{{ $client->name }} wants to:</h2>
    <ul class="consent-scopes">
        @forelse($scopes as $scope)
            <li>{{ $scope->description }}</li>
        @empty
            <li>Connect to your Aether account</li>
        @endforelse
    </ul>
    <form method="POST" action="{{ route('passport.authorizations.approve') }}" data-submit-form>
        @csrf
        <input type="hidden" name="auth_token" value="{{ $authToken }}">
        <x-ui.button class="button--full">Allow</x-ui.button>
    </form>
    <form class="consent-deny" method="POST" action="{{ route('passport.authorizations.deny') }}" data-submit-form>
        @csrf
        @method('DELETE')
        <input type="hidden" name="auth_token" value="{{ $authToken }}">
        <x-ui.button variant="secondary" class="button--full">Deny</x-ui.button>
    </form>
</x-ui.auth-card>
