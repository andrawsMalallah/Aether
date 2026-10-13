<x-ui.auth-card title="Sign in" description="Use your Aether account to continue.">
    <form method="POST" action="{{ route('login.store') }}" data-submit-form>
        @csrf
        <x-ui.field name="email" label="Email address" type="email" autocomplete="username" required autofocus />
        <x-ui.field name="password" label="Password" type="password" autocomplete="current-password" required />
        <a class="auth-card__recovery" href="{{ route('password.request') }}">Forgot password?</a>
        <label class="checkbox"><input type="checkbox" name="remember" value="1" @checked(old('remember'))> Keep me signed in on this device</label>
        <x-ui.button class="button--full">Sign in</x-ui.button>
    </form>
    <p class="auth-card__alternative">New to Aether? <a href="{{ route('register') }}">Create an account</a></p>
</x-ui.auth-card>
