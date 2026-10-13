<x-ui.auth-card title="Verify your sign-in" description="Enter the six-digit code from your authenticator app.">
    <form method="POST" action="{{ route('two-factor.login.store') }}" data-submit-form>
        @csrf
        <x-ui.field name="code" label="Authenticator code" type="password" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" minlength="6" maxlength="6" required autofocus />
        <x-ui.button class="button--full">Verify</x-ui.button>
    </form>
    <details class="recovery-option">
        <summary>Use a recovery code instead</summary>
        <form method="POST" action="{{ route('two-factor.login.store') }}" data-submit-form>
            @csrf
            <x-ui.field name="recovery_code" label="Recovery code" type="password" autocomplete="off" required />
            <x-ui.button class="button--full">Use recovery code</x-ui.button>
        </form>
    </details>
    <p class="auth-card__alternative"><a href="{{ route('login') }}">Back to sign in</a></p>
</x-ui.auth-card>
