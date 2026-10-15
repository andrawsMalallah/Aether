<?php

return [
    // Prism is a local-only browser client; never carry its origin into deployed environments.
    'paths' => ['oauth/token', 'oauth/revoke', 'oauth/userinfo', '.well-known/openid-configuration', '.well-known/jwks.json'],
    'allowed_methods' => ['GET', 'POST', 'OPTIONS'],
    'allowed_origins' => env('APP_ENV', 'production') === 'local' ? ['http://localhost:5173'] : [],
    'allowed_origins_patterns' => [],
    'allowed_headers' => ['Authorization', 'Content-Type', 'Accept'],
    'exposed_headers' => ['WWW-Authenticate'],
    'max_age' => 600,
    'supports_credentials' => false,
];
