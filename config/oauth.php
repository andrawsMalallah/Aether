<?php

return [
    // Administrator-grantable machine permissions; identity scopes never belong to services.
    'machine_scopes' => ['stats:read'],
    'scopes' => [
        'openid' => 'Sign you in',
        'profile' => 'See your name',
        'email' => 'See your email address',
        'stats:read' => 'Read application totals',
    ],
];
