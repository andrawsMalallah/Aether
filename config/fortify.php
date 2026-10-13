<?php

use Laravel\Fortify\Features;

return [
    'guard' => 'web',
    'passwords' => 'users',
    'username' => 'email',
    'email' => 'email',
    'lowercase_usernames' => true,
    'home' => '/account/profile',
    'prefix' => '',
    'domain' => null,
    'middleware' => ['web'],
    'auth_middleware' => 'auth',
    'views' => true,
    'limiters' => ['login' => 'login', 'verification' => 'verification'],
    'features' => [Features::emailVerification()],
];
