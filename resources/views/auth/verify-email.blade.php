<x-ui.auth-card title="Verify your email" description="Open the verification link sent to your email address. You must verify before using your account.">
    <form method="POST" action="{{ route('verification.send') }}" data-submit-form>
        @csrf
        <x-ui.button class="button--full">Send another verification link</x-ui.button>
    </form>
    <form class="auth-card__alternative" method="POST" action="{{ route('logout') }}" data-submit-form>
        @csrf
        <x-ui.button variant="secondary">Sign out</x-ui.button>
    </form>
</x-ui.auth-card>
