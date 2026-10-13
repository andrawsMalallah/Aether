<?php

use App\Providers\AppServiceProvider;
use App\Providers\FortifyServiceProvider;
use App\Providers\OAuthServiceProvider;

return [
    AppServiceProvider::class,
    FortifyServiceProvider::class,
    OAuthServiceProvider::class,
];
