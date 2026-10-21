<?php

namespace App\Services\OAuth;

use Exception;
use Illuminate\Contracts\Encryption\Encrypter;
use Laravel\Passport\Passport;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use League\OAuth2\Server\CryptTrait;

class ReadToken
{
    use CryptTrait;

    public function __construct(Encrypter $encrypter)
    {
        $this->setEncryptionKey(Passport::tokenEncryptionKey($encrypter));
    }

    /** @return array{refresh_token_id: string, client_id: string}|null */
    public function refresh(string $token): ?array
    {
        try {
            $payload = json_decode($this->decrypt($token), true, flags: JSON_THROW_ON_ERROR);
        } catch (Exception) {
            return null;
        }

        return is_array($payload) && is_string($payload['refresh_token_id'] ?? null) && is_string($payload['client_id'] ?? null)
            ? ['refresh_token_id' => $payload['refresh_token_id'], 'client_id' => $payload['client_id']] : null;
    }

    public function access(string $token): ?string
    {
        $keys = app(OidcKeys::class)->publicKeys();
        try {
            $parsed = (new Parser(new JoseEncoder))->parse($token);
            if (! $parsed instanceof UnencryptedToken) {
                return null;
            }
            foreach ($keys as $pem) {
                if ((new Validator)->validate($parsed, new SignedWith(new Sha256, InMemory::plainText($pem)))) {
                    $identifier = $parsed->claims()->get('jti');

                    return is_string($identifier) ? $identifier : null;
                }
            }

            return null;
        } catch (Exception) {
            return null;
        }
    }
}
