<x-layout title="Edit application">
    <x-ui.header />
    <main id="main-content" class="account-content">
        <a href="{{ route('developer.apps.show', $application['id']) }}">Back to application</a>
        <h1>Edit application</h1>
        <p class="page-description developer-application-name">Update the settings for {{ $application['name'] }}.</p>
        <form method="POST" enctype="multipart/form-data" action="{{ route('developer.apps.update', $application['id']) }}" data-submit-form>
            @csrf
            @method('PUT')
            <x-developer.application-fields :scopes="$scopes" :application="$application" />
            <section class="settings-section" aria-labelledby="logo-title">
                <h2 id="logo-title">Application logo</h2>
                <x-ui.application-logo :name="$application['name']" :url="$application['logo_url']" />
                <x-ui.field name="logo" label="Upload a logo (optional)" type="file" accept="image/jpeg,image/png,image/webp" help="PNG, JPEG or WebP, up to 2 MB and 4096 × 4096 pixels. A square image works best. Leave empty to keep the current logo." />
            </section>
            @if(!$application['machine'])
                <p class="page-description">Removing permissions invalidates tokens that use them. Callback changes affect pending and future sign-ins.</p>
            @endif
            <x-ui.button>Save settings</x-ui.button>
        </form>
    </main>
</x-layout>
