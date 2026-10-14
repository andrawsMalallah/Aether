<?php

return [
    // Opt in to exact relying-party origins when browser clients are introduced.
    'paths' => ['oauth/token', 'oauth/revoke', 'oauth/userinfo', '.well-known/openid-configuration', '.well-known/jwks.json'],
    'allowed_methods' => ['GET', 'POST', 'OPTIONS'],
    'allowed_origins' => [],
    'allowed_origins_patterns' => [],
    'allowed_headers' => ['Authorization', 'Content-Type', 'Accept'],
    'exposed_headers' => ['WWW-Authenticate'],
    'max_age' => 600,
    'supports_credentials' => false,
];
