<x-layout title="Register an application">
    <x-ui.header />
    <main id="main-content" class="account-content">
        <a href="{{ route('developer.apps.index') }}">My applications</a>
        <h1>Register an application</h1>
        @if($machine ?? false)
            <p class="page-description">Register a service that calls APIs without signing in a person.</p>
            <p><a href="{{ route('developer.apps.create') }}">Register a Web, Browser or Mobile application instead</a></p>
        @else
            <p class="page-description">Connect your Web, Browser or Mobile application to Sign in with Aether.</p>
            <p><a href="{{ route('developer.apps.machine.create') }}">Register a Machine application</a> for server-to-server API access.</p>
        @endif
        <form method="POST" action="{{ route('developer.apps.store') }}" data-submit-form>
            @csrf
            <x-developer.application-fields :scopes="$scopes" :machine="$machine ?? false" />
            <p class="page-description">{{ ($machine ?? false) ? 'Your application starts in Testing. Token issuance is blocked until an administrator approves permissions and activates it.' : 'Your application starts in Testing. Only you can sign in through it.' }}</p>
            <x-ui.button>Register application</x-ui.button>
        </form>
    </main>
</x-layout>
