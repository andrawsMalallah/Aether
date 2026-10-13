<?php

namespace App\Enums;

enum OAuthClientStatus: string
{
    case Testing = 'testing';
    case Live = 'live';
    case Suspended = 'suspended';
}
