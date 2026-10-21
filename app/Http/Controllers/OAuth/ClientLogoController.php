<?php

namespace App\Http\Controllers\OAuth;

use App\Models\OAuthClient;
use App\Services\PrivateStorage;
use Illuminate\Support\Facades\Gate;
use Symfony\Component\HttpFoundation\StreamedResponse;

class ClientLogoController
{
    public function __invoke(OAuthClient $client): StreamedResponse
    {
        Gate::authorize('viewLogo', $client);
        $disk = PrivateStorage::disk();
        abort_unless($client->logo_path && $disk->exists($client->logo_path), 404);
        abort_unless(in_array($disk->mimeType($client->logo_path), ['image/jpeg', 'image/png', 'image/webp'], true), 404);

        return PrivateStorage::response($client->logo_path, $disk->mimeType($client->logo_path), ['Cache-Control' => 'no-store, private', 'X-Content-Type-Options' => 'nosniff']);
    }
}
