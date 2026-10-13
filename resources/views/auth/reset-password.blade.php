<x-ui.auth-card title="Choose a new password" description="Use a password you have not used on another account.">
    <form method="POST" action="{{ route('password.update') }}" data-submit-form>
        @csrf
        <input type="hidden" name="token" value="{{ $token }}">
        <x-ui.field name="email" label="Email address" type="email" :value="$email" autocomplete="username" required />
        <x-ui.field name="password" label="New password" type="password" autocomplete="new-password" required minlength="8" />
        <x-ui.field name="password_confirmation" label="Confirm new password" type="password" autocomplete="new-password" required />
        <x-ui.button class="button--full">Reset password</x-ui.button>
    </form>
</x-ui.auth-card>
