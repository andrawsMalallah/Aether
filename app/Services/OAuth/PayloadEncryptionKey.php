<?php

namespace App\Services\OAuth;

use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Encryption\Encrypter as FrameworkEncrypter;
use RuntimeException;

class PayloadEncryptionKey
{
    public function resolve(Encrypter $encrypter): string
    {
        $configured = config('oauth_keys.payload_encryption_key');
        if ($configured === null) {
            return $encrypter->getKey();
        }
        if (! is_string($configured) || $configured === '') {
            throw new RuntimeException('OAuth payload encryption configuration is invalid.');
        }
        $key = $configured;
        if (str_starts_with($configured, 'base64:')) {
            $key = base64_decode(substr($configured, 7), true);
            if ($key === false || base64_encode($key) !== substr($configured, 7)) {
                throw new RuntimeException('OAuth payload encryption configuration is invalid.');
            }
        }
        if (! FrameworkEncrypter::supported($key, config('app.cipher'))) {
            throw new RuntimeException('OAuth payload encryption configuration is invalid.');
        }

        return $key;
    }
}
