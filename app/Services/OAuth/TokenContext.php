<?php

namespace App\Services\OAuth;

class TokenContext
{
    public ?string $clientId = null;

    public ?string $authCodeId = null;

    public function reset(): void
    {
        $this->clientId = null;
        $this->authCodeId = null;
    }
}
