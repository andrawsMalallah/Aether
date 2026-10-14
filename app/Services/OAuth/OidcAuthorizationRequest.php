<?php

namespace App\Services\OAuth;

use League\OAuth2\Server\RequestTypes\AuthorizationRequest;

class OidcAuthorizationRequest extends AuthorizationRequest
{
    public ?string $nonce = null;

    public ?int $authTime = null;
}
