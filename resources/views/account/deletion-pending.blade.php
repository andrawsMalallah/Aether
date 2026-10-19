<x-layout title="Account deletion pending">
    <main id="main-content" class="account-content">
        <h1>Account deletion pending</h1>
        <x-ui.status />
        <p>Your account access is disabled. Your personal account data is scheduled for erasure on or after {{ $deletion['due_at'] }}.</p>
        <p>You can cancel before this deadline. Previous sessions, tokens and application approvals will stay revoked.</p>
        <form method="POST" action="{{ route('account.deletion.cancel') }}" data-submit-form>
            @csrf
            <label class="checkbox"><input type="checkbox" name="confirm" value="1" required><span>I want to keep my account and cancel deletion.</span></label>
            @error('confirm')<p class="field__error" role="alert">{{ $message }}</p>@enderror
            <x-ui.button>Cancel account deletion</x-ui.button>
        </form>
        <form class="security-disable" method="POST" action="{{ route('logout') }}">
            @csrf
            <x-ui.button variant="secondary">Sign out</x-ui.button>
        </form>
    </main>
</x-layout>
