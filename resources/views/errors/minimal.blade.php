@php
    // Show a fixed description, never an exception message or request details.
    $statusCode = $exception->getStatusCode();
    $description = match ($statusCode) {
        401 => 'Sign in to continue.',
        403 => 'You do not have permission to view this page.',
        404 => 'We could not find this page. Check the address and try again.',
        419 => 'This page has expired. Reload it and try again.',
        429 => 'Too many requests. Wait a moment and try again.',
        default => $statusCode >= 500
            ? 'Aether cannot complete this request right now. Try again later.'
            : 'Aether could not accept this request. Check it and try again.',
    };
@endphp
<x-ui.auth-card :title="(string) $statusCode" :description="$description" :show-status="false">
    <a href="{{ route('home') }}">Go to Aether home</a>
</x-ui.auth-card>
