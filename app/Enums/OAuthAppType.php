<?php

namespace App\Enums;

enum OAuthAppType: string
{
    case Web = 'web';
    case Spa = 'spa';
    case Mobile = 'mobile';
    case Machine = 'm2m';
}
