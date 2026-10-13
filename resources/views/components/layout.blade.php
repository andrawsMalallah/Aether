@props(['title' => 'Aether'])
<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="referrer" content="no-referrer">
    <title>{{ $title }} · Aether</title>
    <link rel="icon" type="image/svg+xml" href="{{ Vite::asset('resources/images/aether-favicon.svg') }}">
    @vite('resources/js/app.js')
</head>
<body>
    <a class="skip-link" href="#main-content">Skip to content</a>
    {{ $slot }}
</body>
</html>
