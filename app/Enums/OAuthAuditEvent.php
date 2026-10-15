<?php

namespace App\Enums;

enum OAuthAuditEvent: string
{
    case ClientCreated = 'client.created';
    case ClientUpdated = 'client.updated';
    case ClientSecretRegenerated = 'client.secret_regenerated';
    case ClientPublished = 'client.published';
    case ClientSuspended = 'client.suspended';
    case ClientRestored = 'client.restored';
    case ConsentGranted = 'consent.granted';
    case CodeReplayed = 'code.replayed';
    case RefreshReplayed = 'refresh.replayed';
    case TokenRevoked = 'token.revoked';
}
