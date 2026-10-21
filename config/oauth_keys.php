<?php

return [
    // JSON list of public PEM strings, never private keys or remote key URLs.
    'additional_public_keys' => env('OAUTH_VERIFICATION_PUBLIC_KEYS', '[]'),
    // Optional framework-format key. Unset preserves Passport's current APP_KEY behavior.
    'payload_encryption_key' => env('PASSPORT_TOKEN_ENCRYPTION_KEY'),
];
