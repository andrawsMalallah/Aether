<x-layout title="Delete account">
    <x-ui.header />
    <main id="main-content" class="account-content">
        <a href="{{ route('account.security') }}">Back to security</a>
        <h1>Delete account</h1>
        <x-ui.status />
        @if($administrator)
            <p>Administrator accounts cannot use self-service deletion. Arrange an operator review first.</p>
        @else
            <section class="settings-section" aria-labelledby="deletion-effects">
                <h2 id="deletion-effects">What happens next</h2>
                <p>Your Aether access stops immediately. All sessions, remembered sign-ins, tokens and saved approvals are revoked. Export downloads become unavailable.</p>
                <p>You have 14 days to cancel by signing in with your password and existing two-factor authentication. Signing in alone does not cancel deletion.</p>
                <p>After the deadline, your profile, credentials, avatar and export files are erased. A minimal anonymized account reference, audit history and previously deleted application records remain.</p>
                <p>Other applications keep their own data and may keep you signed in. Contact those applications separately.</p>
                <p>Delete all your owned applications first, including suspended apps. Ownership transfer is unavailable.</p>
                <p><a href="{{ route('account.export.index') }}">Download your data before continuing</a>. Wait for your export and save it before requesting deletion.</p>
                <form method="POST" action="{{ route('account.deletion.store') }}" data-submit-form>
                    @csrf
                    <label class="checkbox"><input type="checkbox" name="confirm" value="1" required><span>I understand the consequences and want to delete my Aether account.</span></label>
                    @error('confirm')<p class="field__error" role="alert">{{ $message }}</p>@enderror
                    <x-ui.button>Request account deletion</x-ui.button>
                </form>
            </section>
        @endif
    </main>
</x-layout>
