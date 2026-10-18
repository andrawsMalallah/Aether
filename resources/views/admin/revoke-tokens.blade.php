<x-admin.confirmation :application="$application" title="Revoke tokens"
    description="All this application's access tokens, refresh tokens and pending sign-ins will be revoked. Its status, client secret and permissions stay the same. New sign-ins and token requests remain possible under its current access rules. Existing sessions inside the client app may remain signed in. To stop new access too, suspend the application instead."
    confirmation="I understand and want to revoke this application's tokens and pending sign-ins."
    :action="route('admin.apps.tokens.revoke', $application['id'])" />
