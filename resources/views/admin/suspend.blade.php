<x-admin.confirmation :application="$application" title="Suspend application"
    description="Sign-in and token issuance will stop immediately. All this app's access tokens, refresh tokens and pending sign-ins will be revoked. Existing sessions inside the client app may remain signed in. Restoring later returns the application to Testing."
    confirmation="I understand and want to suspend this application."
    :action="route('admin.apps.suspend', $application['id'])" />
