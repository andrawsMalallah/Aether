<x-layout title="Security">
    <x-ui.header />
    <main id="main-content" class="account-content">
        <h1>Security</h1>
        <p class="page-description">Protect your account with an authenticator app.</p>
        <x-ui.status />
        <section class="settings-section" aria-labelledby="export-title">
            <h2 id="export-title">Account data</h2>
            <p>Prepare a private copy of your Aether account data.</p>
            <a href="{{ route('account.export.index') }}">Export account data</a>
        </section>
        <section class="settings-section" aria-labelledby="connected-apps-title">
            <h2 id="connected-apps-title">Connected apps</h2>
            <p>Review the permissions you approved and disconnect applications.</p>
            <a href="{{ route('account.connected-apps.index') }}">Manage connected apps</a>
        </section>
        <section class="settings-section" aria-labelledby="sessions-title">
            <h2 id="sessions-title">Active sessions</h2>
            <p>Review where your Aether account is signed in and revoke other sessions.</p>
            <a href="{{ route('account.sessions.index') }}">Manage active sessions</a>
        </section>
        <section class="settings-section" aria-labelledby="two-factor-title">
            <h2 id="two-factor-title">Two-factor authentication</h2>
            @if($user->hasEnabledTwoFactorAuthentication())
                <p class="notice">Enabled. Sign-in requires your password and an authenticator or recovery code.</p>
                @if(count($recoveryCodes))
                    <h2>Save your recovery codes</h2>
                    <p class="page-description">Each code works once. Store these somewhere safe. They are shown only now; regenerate them if you lose them.</p>
                    <ul class="recovery-codes" aria-label="Recovery codes">
                        @foreach($recoveryCodes as $recoveryCode)
                            <li><code>{{ $recoveryCode }}</code></li>
                        @endforeach
                    </ul>
                @endif
                <form method="POST" action="{{ route('account.two-factor.regenerate') }}" data-submit-form>
                    @csrf
                    <p class="page-description">Generating new recovery codes invalidates all previous codes.</p>
                    <x-ui.button>Generate new recovery codes</x-ui.button>
                </form>
            @elseif($user->two_factor_secret)
                <p class="page-description">Scan this QR code with your authenticator app. Setup stays inactive until you confirm a code.</p>
                {{-- Fortify generates this SVG locally; no user-supplied markup is rendered. --}}
                <div class="two-factor-qr" role="img" aria-label="Authenticator setup QR code">{!! $user->twoFactorQrCodeSvg() !!}</div>
                <p class="page-description">Cannot scan? Enter this setup key in your app:</p>
                <p class="setup-key"><code>{{ \Laravel\Fortify\Fortify::currentEncrypter()->decrypt($user->two_factor_secret) }}</code></p>
                <form method="POST" action="{{ route('account.two-factor.confirm') }}" data-submit-form>
                    @csrf
                    <x-ui.field name="code" label="Authenticator code" type="password" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" minlength="6" maxlength="6" required />
                    <x-ui.button>Confirm setup</x-ui.button>
                </form>
            @else
                <p class="page-description">Add a second step to sign-in using an authenticator app on your phone.</p>
                <form method="POST" action="{{ route('account.two-factor.enable') }}" data-submit-form>
                    @csrf
                    <x-ui.button>Set up two-factor authentication</x-ui.button>
                </form>
            @endif
            @if($user->two_factor_secret)
                <form class="security-disable" method="POST" action="{{ route('account.two-factor.disable') }}" data-submit-form>
                    @csrf
                    @method('DELETE')
                    <x-ui.button variant="secondary">{{ $user->hasEnabledTwoFactorAuthentication() ? 'Disable two-factor authentication' : 'Cancel setup' }}</x-ui.button>
                </form>
            @endif
        </section>
    </main>
</x-layout>
