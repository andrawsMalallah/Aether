<header class="site-header">
    <x-ui.logo />
    <nav class="site-nav" aria-label="Account navigation">
        @auth
            <a href="{{ route('account.profile') }}">Your account</a>
            <form method="POST" action="{{ route('logout') }}" data-submit-form>
                @csrf
                <x-ui.button variant="secondary">Sign out</x-ui.button>
            </form>
        @else
            <a href="{{ route('register') }}">Create an account</a>
            <a class="button button--primary" href="{{ route('login') }}">Sign in</a>
        @endauth
    </nav>
</header>
