<?php

namespace Database\Seeders;

use App\Enums\OAuthAppType;
use App\Enums\OAuthClientStatus;
use App\Models\OAuthClient;
use Illuminate\Database\Seeder;
use Laravel\Passport\ClientRepository;

class OAuthTestClientSeeder extends Seeder
{
    public function run(): void
    {
        if (! app()->environment('local')) {
            return;
        }
        if (OAuthClient::query()->where('name', 'Aether local OAuth walkthrough')->exists()) {
            return;
        }
        // Public local fixture: no client secret to put in shell history or logs.
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Aether local OAuth walkthrough', ['http://localhost:8765/callback'], false);
        $client->forceFill([
            'status' => OAuthClientStatus::Live,
            'app_type' => OAuthAppType::Spa,
            'allowed_scopes' => ['openid', 'profile', 'email'],
        ])->save();
    }
}
