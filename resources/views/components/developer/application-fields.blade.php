@props(['scopes', 'application' => null])
@php($selectedScopes = $application ? array_keys($application['scopes']) : ['openid'])
@if($errors->any())
    <div class="notice notice--error" role="alert">
        <p>Check your application details.</p>
        <ul>@foreach($errors->all() as $error)<li>{{ $error }}</li>@endforeach</ul>
    </div>
@endif
<section class="settings-section" aria-labelledby="details-title">
    <h2 id="details-title">Application details</h2>
    <x-ui.field name="name" label="Application name" :value="$application['name'] ?? null" required maxlength="255" />
    <x-ui.field name="homepage_url" label="Homepage URL (optional)" type="url" :value="$application['homepage_url'] ?? null" maxlength="2048" help="Use an HTTPS address." />
    <x-ui.textarea name="redirect_urls" label="Callback URLs" rows="4" required maxlength="22000"
        :value="$application ? implode(PHP_EOL, $application['redirect_uris']) : null"
        :error-name="$errors->has('redirect_uris') ? 'redirect_uris' : 'redirect_uris.*'"
        help="One exact URL per line, up to 10. Use HTTPS, or HTTP on localhost/loopback for development. Wildcards are not allowed." />
</section>
<fieldset class="developer-scopes">
    <legend>Identity permissions</legend>
    <p class="page-description">Choose the information your application needs. Sign you in is required.</p>
    @foreach($scopes as $scope => $label)
        <label class="checkbox">
            <input type="checkbox" name="scopes[]" value="{{ $scope }}" @checked(in_array($scope, is_array(old('scopes')) ? old('scopes') : $selectedScopes, true))>
            <span>{{ $label }}</span>
        </label>
    @endforeach
</fieldset>
