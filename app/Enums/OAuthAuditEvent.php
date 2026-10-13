<?php

namespace App\Enums;

enum OAuthAuditEvent: string
{
    case ConsentGranted = 'consent.granted';
    case CodeReplayed = 'code.replayed';
    case RefreshReplayed = 'refresh.replayed';
    case TokenRevoked = 'token.revoked';
}
