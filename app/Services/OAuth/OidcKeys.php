<?php

namespace App\Services\OAuth;

use Laravel\Passport\Passport;
use Lcobucci\JWT\Signer\Key\InMemory;
use RuntimeException;
use Throwable;

class OidcKeys
{
    /** @var array{private: string, public: string, ring: array<string, string>, jwks: list<array<string, string>>}|null */
    private ?array $material = null;

    public function privateKey(): InMemory
    {
        return InMemory::plainText($this->material()['private']);
    }

    public function publicKey(): InMemory
    {
        return InMemory::plainText($this->material()['public']);
    }

    /** @return array<string, string> */
    public function jwk(): array
    {
        return $this->material()['jwks'][0];
    }

    /** @return list<array<string, string>> */
    public function jwks(): array
    {
        return $this->material()['jwks'];
    }

    /** @return array<string, string> Public fingerprint => public PEM */
    public function publicKeys(): array
    {
        return $this->material()['ring'];
    }

    /** @return array{private: string, public: string, ring: array<string, string>, jwks: list<array<string, string>>} */
    private function material(): array
    {
        if ($this->material !== null) {
            return $this->material;
        }
        try {
            $private = $this->readActive('private');
            $public = $this->readActive('public');
            $active = $this->publicDetails($public);
            $privateResource = @openssl_pkey_get_private($private);
            $privateDetails = $privateResource === false ? false : openssl_pkey_get_details($privateResource);
            if ($privateDetails === false || ! isset($privateDetails['rsa'])
                || $privateDetails['rsa']['n'] !== $active['rsa']['n'] || $privateDetails['rsa']['e'] !== $active['rsa']['e']) {
                throw new RuntimeException;
            }
            $additional = config('oauth_keys.additional_public_keys', '[]');
            $additional = is_string($additional) ? json_decode($additional, true, flags: JSON_THROW_ON_ERROR) : $additional;
            if (! is_array($additional) || ! array_is_list($additional) || count($additional) > 3) {
                throw new RuntimeException;
            }
            $ring = [];
            $jwks = [];
            foreach ([$public, ...$additional] as $pem) {
                if (! is_string($pem)) {
                    throw new RuntimeException;
                }
                $pem = str_replace('\\n', "\n", $pem);
                $jwk = $this->toJwk($this->publicDetails($pem));
                if (! isset($ring[$jwk['kid']])) {
                    $ring[$jwk['kid']] = $pem;
                    $jwks[] = $jwk;
                }
            }
            if (count($ring) > 3) {
                throw new RuntimeException;
            }

            return $this->material = compact('private', 'public', 'ring', 'jwks');
        } catch (Throwable) {
            // Configuration errors must never reveal key material or crypto-library messages.
            throw new RuntimeException('OAuth signing key configuration is invalid.');
        }
    }

    private function readActive(string $type): string
    {
        $configured = config('passport.'.$type.'_key');
        if ($configured === null || $configured === '') {
            $configured = @file_get_contents(Passport::keyPath('oauth-'.$type.'.key'));
        }
        if (! is_string($configured) || $configured === '') {
            throw new RuntimeException;
        }

        return str_replace('\\n', "\n", $configured);
    }

    /** @return array{rsa: array{n: string, e: string}} */
    private function publicDetails(string $pem): array
    {
        // OpenSSL also accepts file:// references. Only in-memory public PEM is
        // allowed here; default active file paths are resolved by readActive.
        $header = ltrim($pem);
        if (! str_starts_with($header, '-----BEGIN PUBLIC KEY-----') && ! str_starts_with($header, '-----BEGIN RSA PUBLIC KEY-----')) {
            throw new RuntimeException;
        }
        $resource = @openssl_pkey_get_public($pem);
        $details = $resource === false ? false : openssl_pkey_get_details($resource);
        if ($details === false || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA
            || ($details['bits'] ?? 0) < 2048 || ! isset($details['rsa']['n'], $details['rsa']['e'])) {
            throw new RuntimeException;
        }

        return ['rsa' => ['n' => $details['rsa']['n'], 'e' => $details['rsa']['e']]];
    }

    /** @param array{rsa: array{n: string, e: string}} $details
     * @return array<string, string>
     */
    private function toJwk(array $details): array
    {
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
