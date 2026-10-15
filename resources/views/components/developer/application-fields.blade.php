@props(['scopes', 'application' => null, 'machine' => false])
@php($machine = $application['machine'] ?? $machine)
@php($selectedScopes = $application ? array_keys($application['scopes']) : ['openid'])
@if($errors->any())
    <div class="notice notice--error" role="alert">
        <p>Check your application details.</p>
        <ul>@foreach($errors->all() as $error)<li>{{ $error }}</li>@endforeach</ul>
    </div>
@endif
<section class="settings-section" aria-labelledby="details-title">
    <h2 id="details-title">Application details</h2>
    @if($application === null && $machine)
        <input type="hidden" name="app_type" value="m2m">
        <p class="page-description">Machine application. Uses server-to-server credentials without a user login. The type cannot be changed after registration.</p>
    @elseif($application === null)
        <x-ui.select name="app_type" label="Application type" :value="is_string(old('app_type')) ? old('app_type') : 'web'" placeholder="Choose a type"
            :options="['web' => 'Web application (server-side)', 'spa' => 'Browser application (SPA)', 'mobile' => 'Mobile application (native)']" />
        <p class="page-description">Web applications keep a secret on their server. Browser and Mobile applications use PKCE without a secret. Mobile callbacks require HTTPS app/universal links. The type cannot be changed after registration.</p>
    @else
        <p class="page-description">{{ $application['type'] }}. The application type cannot be changed.</p>
    @endif
    <x-ui.field name="name" label="Application name" :value="$application['name'] ?? null" required maxlength="255" />
    <x-ui.field name="homepage_url" label="Homepage URL (optional)" type="url" :value="$application['homepage_url'] ?? null" maxlength="2048" help="Use an HTTPS address." />
    @if(!$machine)
    <x-ui.textarea name="redirect_urls" label="Callback URLs" rows="4" required maxlength="22000"
        :value="$application ? implode(PHP_EOL, $application['redirect_uris']) : null"
        :error-name="$errors->has('redirect_uris') ? 'redirect_uris' : 'redirect_uris.*'"
        :help="($application['mobile'] ?? false) ? 'One exact HTTPS app/universal link per line, up to 10. Configure the domain association in your native app. Custom schemes, HTTP and wildcards are not supported.' : 'One exact URL per line, up to 10. Mobile apps require HTTPS app/universal links. Web and Browser apps may use HTTP on localhost/loopback for development. Wildcards are not allowed.'" />
    @endif
</section>
@if($machine)
    <p class="notice">API permissions and activation require administrator approval. Contact the Aether operator with your client ID and the API access you need. Owner settings cannot grant permissions.</p>
@else
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
@endif
