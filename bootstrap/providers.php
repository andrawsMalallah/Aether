<?php

use App\Providers\AppServiceProvider;
use App\Providers\DiagnosticsServiceProvider;
use App\Providers\FortifyServiceProvider;
use App\Providers\OAuthServiceProvider;

return [
    DiagnosticsServiceProvider::class,
    AppServiceProvider::class,
    FortifyServiceProvider::class,
    OAuthServiceProvider::class,
];
