<x-ui.auth-card title="Reset your password" description="Enter your email address to request a reset link.">
    <form method="POST" action="{{ route('password.email') }}" data-submit-form>
        @csrf
        <x-ui.field name="email" label="Email address" type="email" autocomplete="email" required autofocus />
        <x-ui.button class="button--full">Send reset link</x-ui.button>
    </form>
    <p class="auth-card__alternative"><a href="{{ route('login') }}">Back to sign in</a></p>
</x-ui.auth-card>
