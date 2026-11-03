<x-layout title="Terms of service">
    <x-ui.header />
    <main id="main-content" class="public-content">
        <h1>Terms of service</h1>
        <p class="notice">Draft placeholder — Aether is a development project and is not open for production use.</p>
        <p class="page-description">These temporary terms explain how to use Aether during development and testing. They will be replaced with owner-approved terms before public launch.</p>

        <section class="settings-section">
            <h2>About Aether</h2>
            <p>Aether provides a central account you can use to sign in to connected applications. Each application operates separately and may have its own terms and privacy policy.</p>
        </section>

        <section class="settings-section">
            <h2>Your account</h2>
            <p>Use an email address you control, keep your password and recovery codes private, and review your account security settings. Do not share another person's account or try to access accounts without permission.</p>
            <p>You can review your details on your <a href="{{ route('account.profile') }}">profile</a> and manage sign-in protection on the <a href="{{ route('account.security') }}">security page</a>. These pages require sign-in.</p>
        </section>

        <section class="settings-section">
            <h2>Connected applications</h2>
            <p>Review the application name and requested permissions before approving a sign-in. Only connect applications you trust. Some trusted integrations may sign you in without asking for a separate saved approval.</p>
            <p>You can withdraw saved approvals in <a href="{{ route('account.connected-apps.index') }}">Connected apps</a>. Disconnecting an application does not erase information it already received or necessarily end its own signed-in session.</p>
        </section>

        <section class="settings-section">
            <h2>Responsible testing</h2>
            <p>Use Aether only for authorized development and testing. Do not use it to impersonate others, collect their credentials, bypass access controls, send spam, or disrupt the service. Security testing must stay within the scope agreed with the project owner.</p>
        </section>

        <section class="settings-section">
            <h2>Availability and account closure</h2>
            <p>Features may change and the service may be interrupted while Aether is in development. Do not rely on it for production access or as the only way to recover access to another service.</p>
            <p>Account deletion can be requested from your profile, subject to the checks and grace period shown there. Connected applications manage their own accounts and data separately.</p>
        </section>

        <section class="settings-section">
            <h2>Before public launch</h2>
            <p>The final terms still need the operator's identity and contact details, applicable jurisdiction, and reviewed rules for service changes, suspension, liability, and disputes.</p>
            <p>See the <a href="{{ route('privacy') }}">draft privacy policy</a> for an overview of how the development service handles information.</p>
        </section>
    </main>
</x-layout>
