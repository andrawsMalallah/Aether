<x-layout title="One identity, every application">
    <x-ui.header />
    <main id="main-content" class="welcome">
        <h1 class="welcome__title">One identity, every application.</h1>
        <p class="welcome__description">Your Aether account keeps your sign-in details in one place.</p>
        <a class="button button--primary" href="{{ route('register') }}">Create an account</a>
        <p class="welcome__description">Already registered? <a href="{{ route('login') }}">Sign in</a></p>
    </main>
</x-layout>
