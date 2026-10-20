<?php

namespace App\Enums;

enum LoginLockoutStage: string
{
    case Password = 'password';
    case TwoFactor = 'two_factor';
}
