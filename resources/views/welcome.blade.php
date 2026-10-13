<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{{ config('app.name') }}</title>
        @vite('resources/js/app.js')
    </head>
    <body>
        <main class="welcome">
            <div class="welcome__brand">AETHER</div>
            <h1 class="welcome__title">One identity, every application.</h1>
            <p class="welcome__description">Aether is being prepared. Account registration and sign-in will be available soon.</p>
        </main>
    </body>
</html>
