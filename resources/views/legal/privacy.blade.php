<x-layout title="Privacy policy">
    <x-ui.header />
    <main id="main-content" class="public-content">
        <h1>Privacy policy</h1>
        <p class="notice">Draft placeholder — the complete policy must be published before public launch.</p>
        <p class="page-description">This temporary notice describes Aether's current account and sign-in features. It will be replaced with an owner-approved privacy policy before public launch.</p>

        <section class="settings-section">
            <h2>Information used to run your account</h2>
            <p>Aether stores account details such as your name, email address, password hash, and optional profile image. If you enable two-factor authentication, it also stores the information needed to verify that second step and support recovery.</p>
            <p>The service uses account, session, application-approval, and security-event records to provide sign-in, protect accounts, and manage connected applications. Developer accounts also have records for the applications they register.</p>
        </section>

        <section class="settings-section">
            <h2>Information shared with connected applications</h2>
            <p>When you sign in to an application through Aether, it receives identity information allowed by its permissions. This can include an account identifier, profile details, and your email address. Review the permissions shown during approval; trusted integrations may not show a separate approval screen.</p>
            <p>Aether does not give connected applications your Aether password or two-factor recovery codes. Each application is responsible for the information it receives and may retain it under its own policy.</p>
            <p>Use <a href="{{ route('account.connected-apps.index') }}">Connected apps</a> to withdraw saved approvals. This revokes the relevant Aether credentials but does not delete information already held by the application or necessarily sign you out of it.</p>
        </section>

        <section class="settings-section">
            <h2>Cookies and security messages</h2>
            <p>Aether uses cookies to maintain your signed-in session and protect requests. If selected, Remember me supports later sign-in. A separate browser-recognition cookie helps decide when to send a new-browser sign-in alert; it does not replace your password or second factor.</p>
            <p>The service sends account messages such as email verification, password resets, and security notifications. Email delivery and any configured private file storage depend on the services used for the environment.</p>
        </section>

        <section class="settings-section">
            <h2>Your account controls</h2>
            <p>After signing in, you can update your <a href="{{ route('account.profile') }}">profile</a>, review <a href="{{ route('account.security') }}">security settings</a>, request an <a href="{{ route('account.export.index') }}">account export</a>, and request account deletion from your profile. Some actions require email verification or a recent password confirmation.</p>
            <p>Deletion follows the confirmation process and grace period shown in the account interface. It does not automatically remove records held by connected applications, messages already delivered, or backup copies. Security and audit records may remain with identifying account details removed during finalization.</p>
        </section>

        <section class="settings-section">
            <h2>Details still to be confirmed</h2>
            <p>The final policy must identify the operator and privacy contact, the providers and processing locations actually used, applicable data-processing grounds and rights, and the retention and backup-deletion periods that will apply at launch.</p>
            <p>These details are not yet finalized. This draft does not establish a public-launch privacy policy. See the <a href="{{ route('terms') }}">draft terms of service</a> for the current development-use notice.</p>
        </section>
    </main>
</x-layout>
