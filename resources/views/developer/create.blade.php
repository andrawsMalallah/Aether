<x-layout title="Register a web application">
    <x-ui.header />
    <main id="main-content" class="account-content">
        <a href="{{ route('developer.apps.index') }}">My applications</a>
        <h1>Register a web application</h1>
        <p class="page-description">Connect your server-side application to Sign in with Aether.</p>
        <form method="POST" action="{{ route('developer.apps.store') }}" data-submit-form>
            @csrf
            <x-developer.application-fields :scopes="$scopes" />
            <p class="page-description">Your application starts in Testing. Only you can sign in through it.</p>
            <x-ui.button>Register application</x-ui.button>
        </form>
    </main>
</x-layout>
