<?php

it('restricts the configured Prism browser origin to the local environment', function (): void {
    $originalEnvironment = $_ENV['APP_ENV'];
    $originalServerEnvironment = $_SERVER['APP_ENV'] ?? null;
    try {
        foreach (['local', 'testing', 'staging', 'production'] as $environment) {
            $_ENV['APP_ENV'] = $environment;
            $_SERVER['APP_ENV'] = $environment;
            $settings = require base_path('config/cors.php');
            expect($settings['allowed_origins'])->toBe($environment === 'local' ? ['http://localhost:5173'] : [])
                ->and($settings['supports_credentials'])->toBeFalse()
                ->and($settings['allowed_origins_patterns'])->toBe([]);
        }
    } finally {
        $_ENV['APP_ENV'] = $originalEnvironment;
        if ($originalServerEnvironment === null) {
            unset($_SERVER['APP_ENV']);
        } else {
            $_SERVER['APP_ENV'] = $originalServerEnvironment;
        }
    }
});

it('allows only the exact Prism origin on protocol endpoints without credential cookies', function (): void {
    config(['cors.allowed_origins' => ['http://localhost:5173']]);
    $this->getJson('/.well-known/openid-configuration', ['Origin' => 'http://localhost:5173'])
        ->assertHeader('Access-Control-Allow-Origin', 'http://localhost:5173')->assertHeaderMissing('Access-Control-Allow-Credentials');
    foreach (['http://localhost:5174', 'http://127.0.0.1:5173', 'https://attacker.example'] as $origin) {
        $response = $this->getJson('/.well-known/jwks.json', ['Origin' => $origin]);
        // With one allowed origin the CORS library may return it as a fixed header;
        // browsers still reject a response unless it equals the requesting origin.
        expect($response->headers->get('Access-Control-Allow-Origin'))->not->toBe($origin);
    }
    foreach (['/oauth/token', '/oauth/userinfo', '/oauth/revoke'] as $endpoint) {
        $this->options($endpoint, [], ['Origin' => 'http://localhost:5173', 'Access-Control-Request-Method' => 'POST', 'Access-Control-Request-Headers' => 'authorization,content-type'])
            ->assertNoContent()->assertHeader('Access-Control-Allow-Origin', 'http://localhost:5173')
            ->assertHeaderMissing('Access-Control-Allow-Credentials');
    }
    $this->get('/login', ['Origin' => 'http://localhost:5173'])->assertHeaderMissing('Access-Control-Allow-Origin');
});
