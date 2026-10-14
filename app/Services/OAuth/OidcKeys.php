<?php

namespace App\Services\OAuth;

use Laravel\Passport\Passport;
use Lcobucci\JWT\Signer\Key\InMemory;
use RuntimeException;

class OidcKeys
{
    public function privateKey(): InMemory
    {
        $configured = config('passport.private_key');

        return is_string($configured) && $configured !== ''
            ? InMemory::plainText(str_replace('\\n', "\n", $configured))
            : InMemory::file(Passport::keyPath('oauth-private.key'));
    }

    public function publicKey(): InMemory
    {
        $configured = config('passport.public_key');

        return is_string($configured) && $configured !== ''
            ? InMemory::plainText(str_replace('\\n', "\n", $configured))
            : InMemory::file(Passport::keyPath('oauth-public.key'));
    }

    /** @return array<string, string> */
    public function jwk(): array
    {
        $publicKey = openssl_pkey_get_public($this->publicKey()->contents());
        $details = $publicKey === false ? false : openssl_pkey_get_details($publicKey);
        if ($details === false || ! isset($details['rsa'])) {
            throw new RuntimeException('The OIDC public signing key must be RSA.');
        }
        // kid is a public-key fingerprint, stable across PEM formatting changes.
        $modulus = self::base64Url($details['rsa']['n']);
        $exponent = self::base64Url($details['rsa']['e']);
        $thumbprint = json_encode(['e' => $exponent, 'kty' => 'RSA', 'n' => $modulus], JSON_THROW_ON_ERROR);

        return ['kty' => 'RSA', 'use' => 'sig', 'alg' => 'RS256', 'kid' => self::base64Url(hash('sha256', $thumbprint, true)), 'n' => $modulus, 'e' => $exponent];
    }

    private static function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
