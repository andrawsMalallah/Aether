<?php

namespace App\Services\OAuth;

class TokenContext
{
    public ?string $clientId = null;

    public ?string $authCodeId = null;

    public ?OidcAuthorizationRequest $authorization = null;

    public ?int $authTime = null;

    public ?string $nonce = null;

    public function reset(): void
    {
        $this->clientId = null;
        $this->authCodeId = null;
        $this->authorization = null;
        $this->authTime = null;
        $this->nonce = null;
    }
}
