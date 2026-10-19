<?php

namespace App\Enums;

enum OAuthAuditEvent: string
{
    case AccountExported = 'account.exported';
    case AccountDeletionRequested = 'account.deletion_requested';
    case AccountDeletionCancelled = 'account.deletion_cancelled';
    case AccountDeleted = 'account.deleted';
    case LoginSucceeded = 'login.success';
    case LoginFailed = 'login.failed';
    case LoginLockedOut = 'login.locked_out';
    case Logout = 'logout';
    case TwoFactorEnabled = '2fa.enabled';
    case TwoFactorDisabled = '2fa.disabled';
    case TwoFactorFailed = '2fa.failed';
    case RecoveryCodesRegenerated = '2fa.recovery_codes_regenerated';
    case PasswordChanged = 'password.changed';
    case PasswordReset = 'password.reset';
    case EmailChangeRequested = 'email.change_requested';
    case EmailVerified = 'email.verified';
    case TokenIssued = 'token.issued';
    case TokenRefreshed = 'token.refreshed';
    case ClientCreated = 'client.created';
    case ClientUpdated = 'client.updated';
    case ClientSecretRegenerated = 'client.secret_regenerated';
    case ClientPublished = 'client.published';
    case MachineApproved = 'client.machine_approved';
    case ClientSuspended = 'client.suspended';
    case ClientTokensRevoked = 'client.tokens_revoked';
    case ClientRestored = 'client.restored';
    case ClientDeleted = 'client.deleted';
    case ConsentGranted = 'consent.granted';
    case ConsentRevoked = 'consent.revoked';
    case CodeReplayed = 'code.replayed';
    case RefreshReplayed = 'refresh.replayed';
    case TokenRevoked = 'token.revoked';
    case SessionRevoked = 'session.revoked';
}
