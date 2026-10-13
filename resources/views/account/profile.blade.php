<x-layout title="Your account">
    <x-ui.header />
    <main id="main-content" class="account-content">
        <h1>Your account</h1>
        <p class="page-description">Manage your profile and sign-in details.</p>
        <x-ui.status />
        <section class="settings-section" aria-labelledby="profile-title">
            <h2 id="profile-title">Profile</h2>
            @if($user->avatar_path)
                <img class="avatar" src="{{ route('account.avatar') }}" alt="Your current profile photo" width="80" height="80">
            @endif
            <form method="POST" action="{{ route('account.profile.update') }}" enctype="multipart/form-data" data-submit-form>
                @csrf
                @method('PUT')
                <x-ui.field name="name" label="Name" :value="$user->name" autocomplete="name" required maxlength="255" />
                <x-ui.field name="avatar" label="Profile photo" type="file" accept="image/jpeg,image/png,image/webp" help="JPEG, PNG, or WebP, up to 2 MB." />
                <x-ui.button>Save profile</x-ui.button>
            </form>
        </section>
        <section class="settings-section" aria-labelledby="email-title">
            <h2 id="email-title">Email address</h2>
            <p class="page-description">Your current verified address is {{ $user->email }}.</p>
            @if($user->pending_email)
                <p class="notice" role="status">Confirmation is pending for {{ $user->pending_email }}. Your current address is still active.</p>
            @endif
            <form method="POST" action="{{ route('account.email.update') }}" data-submit-form>
                @csrf
                @method('PUT')
                <x-ui.field name="email" label="New email address" type="email" autocomplete="email" required />
                <x-ui.field name="current_password" id="email-current-password" label="Current password" type="password" autocomplete="current-password" required />
                <x-ui.button>Send confirmation link</x-ui.button>
            </form>
        </section>
        <section class="settings-section" aria-labelledby="password-title">
            <h2 id="password-title">Password</h2>
            <p class="page-description">Changing your password signs out your other sessions.</p>
            <form method="POST" action="{{ route('account.password.update') }}" data-submit-form>
                @csrf
                @method('PUT')
                <x-ui.field name="current_password" id="password-current-password" label="Current password" type="password" autocomplete="current-password" required />
                <x-ui.field name="password" label="New password" type="password" autocomplete="new-password" required minlength="8" />
                <x-ui.field name="password_confirmation" label="Confirm new password" type="password" autocomplete="new-password" required />
                <x-ui.button>Change password</x-ui.button>
            </form>
        </section>
    </main>
</x-layout>
