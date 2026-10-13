<?php

namespace App\Http\Controllers\OAuth;

use App\Models\OAuthClient;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Storage;
use Symfony\Component\HttpFoundation\StreamedResponse;

class ClientLogoController
{
    public function __invoke(OAuthClient $client): StreamedResponse
    {
        Gate::authorize('authorize', $client);
        $disk = Storage::disk('local');
        abort_unless($client->logo_path && $disk->exists($client->logo_path), 404);
        abort_unless(in_array($disk->mimeType($client->logo_path), ['image/jpeg', 'image/png', 'image/webp'], true), 404);

        return $disk->response($client->logo_path, null, ['Cache-Control' => 'no-store, private', 'X-Content-Type-Options' => 'nosniff']);
    }
}
