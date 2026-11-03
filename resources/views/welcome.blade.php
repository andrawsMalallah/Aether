<x-layout :title="auth()->check() ? 'Welcome back' : 'One identity, every application'">
    <x-ui.header />
    <main id="main-content" class="welcome">
        @auth
            <h1 class="welcome__title">Welcome back.</h1>
            <p class="welcome__description">Manage your profile, security settings, and connected applications from your account.</p>
            <a class="button button--primary" href="{{ route('account.profile') }}">Open your account</a>
        @else
            <h1 class="welcome__title">One identity, every application.</h1>
            <p class="welcome__description">Your Aether account keeps your sign-in details in one place.</p>
            <a class="button button--primary" href="{{ route('register') }}">Create an account</a>
            <p class="welcome__description">Already registered? <a href="{{ route('login') }}">Sign in</a></p>
        @endauth
    </main>
</x-layout>
