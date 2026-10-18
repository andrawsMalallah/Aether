<?php

namespace App\Enums;

enum AccountExportStatus: string
{
    case Pending = 'pending';
    case ReadyToNotify = 'ready_to_notify';
    case Ready = 'ready';
    case Failed = 'failed';
    case Expired = 'expired';
}
