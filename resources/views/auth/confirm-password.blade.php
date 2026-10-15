<x-ui.auth-card title="Confirm your password" description="Confirm your password to continue with this sensitive change. Confirmation lasts five minutes.">
    <form method="POST" action="{{ route('password.confirm.store') }}" data-submit-form>
        @csrf
        <x-ui.field name="password" label="Password" type="password" autocomplete="current-password" required autofocus />
        <x-ui.button class="button--full">Continue</x-ui.button>
    </form>
    <p class="auth-card__alternative"><a href="{{ route('account.profile') }}">Back to your account</a></p>
</x-ui.auth-card>
