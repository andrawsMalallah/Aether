<x-layout title="Edit application">
    <x-ui.header />
    <main id="main-content" class="account-content">
        <a href="{{ route('developer.apps.show', $application['id']) }}">Back to application</a>
        <h1>Edit application</h1>
        <p class="page-description developer-application-name">Update the settings for {{ $application['name'] }}.</p>
        <form method="POST" action="{{ route('developer.apps.update', $application['id']) }}" data-submit-form>
            @csrf
            @method('PUT')
            <x-developer.application-fields :scopes="$scopes" :application="$application" />
            <p class="page-description">Removing permissions invalidates tokens that use them. Callback changes affect pending and future sign-ins.</p>
            <x-ui.button>Save settings</x-ui.button>
        </form>
    </main>
</x-layout>
