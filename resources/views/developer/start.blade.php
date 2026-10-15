<x-layout title="Developer access">
    <x-ui.header />
    <main id="main-content" class="account-content">
        <h1>Build with Aether</h1>
        <p class="page-description">Let people sign in to your applications with their Aether account.</p>
        <x-ui.status />
        <section class="settings-section" aria-labelledby="developer-title">
            <h2 id="developer-title">Developer access</h2>
            <p>Enable developer access to see the applications you own.</p>
            <form method="POST" action="{{ route('account.developer.enable') }}" data-submit-form>
                @csrf
                <x-ui.button>Become a developer</x-ui.button>
            </form>
        </section>
    </main>
</x-layout>
