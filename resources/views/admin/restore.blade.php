<x-admin.confirmation :application="$application" title="Restore application"
    :description="($application['owner_id'] === null ? 'No owner is assigned; nobody can sign in while this app is Testing until ownership is assigned separately. ' : '').'The application will return to Testing, where only its owner can sign in. Previous tokens and pending sign-ins will remain invalid. Web application owners can choose Go live separately from their developer settings. Other application types require a separately supported publication flow.'"
    confirmation="I understand and want to restore this application to Testing."
    :action="route('admin.apps.restore', $application['id'])" />
