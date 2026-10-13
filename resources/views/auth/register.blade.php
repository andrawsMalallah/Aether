<x-ui.auth-card title="Create an account" description="One account for the applications you trust.">
    <form method="POST" action="{{ route('register.store') }}" data-submit-form>
        @csrf
        <x-ui.field name="name" label="Name" autocomplete="name" required autofocus maxlength="255" />
        <x-ui.field name="email" label="Email address" type="email" autocomplete="email" required maxlength="255" />
        <x-ui.field name="password" label="Password" type="password" autocomplete="new-password" help="Use at least 8 characters. Passwords found in known breaches are rejected." required minlength="8" />
        <x-ui.field name="password_confirmation" label="Confirm password" type="password" autocomplete="new-password" required />
        <label class="checkbox"><input type="checkbox" name="terms" value="1" required @checked(old('terms'))> <span>I agree to the <a href="{{ route('terms') }}">terms of service</a> and <a href="{{ route('privacy') }}">privacy policy</a>.</span></label>
        <x-ui.button class="button--full">Create account</x-ui.button>
    </form>
    <p class="auth-card__alternative">Already registered? <a href="{{ route('login') }}">Sign in</a></p>
</x-ui.auth-card>
