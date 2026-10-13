@props(['title', 'description'])
<x-layout :title="$title">
    <main id="main-content" class="auth-shell">
        <section class="auth-card" aria-labelledby="auth-title">
            <x-ui.logo />
            <h1 id="auth-title">{{ $title }}</h1>
            <p class="auth-card__description">{{ $description }}</p>
            <x-ui.status />
            {{ $slot }}
            <footer class="auth-card__footer">
                <a href="{{ route('terms') }}">Terms of service</a>
                <a href="{{ route('privacy') }}">Privacy policy</a>
            </footer>
        </section>
    </main>
</x-layout>
