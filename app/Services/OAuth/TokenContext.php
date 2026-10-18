<?php

namespace App\Services\OAuth;

class TokenContext
{
    public ?string $clientId = null;

    public ?string $authCodeId = null;

    public ?OidcAuthorizationRequest $authorization = null;

    public ?int $authTime = null;

    public ?string $nonce = null;

    /** @var array{user_id: string|null, client_id: string}|null */
    public ?array $issuedCredentialOwner = null;

    public function reset(): void
    {
        $this->clientId = null;
        $this->authCodeId = null;
        $this->authorization = null;
        $this->authTime = null;
        $this->nonce = null;
        $this->issuedCredentialOwner = null;
    }
}
