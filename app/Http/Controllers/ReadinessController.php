<?php

namespace App\Http\Controllers;

use App\Services\Deployment\DatabaseReadiness;
use Illuminate\Http\Response;

class ReadinessController
{
    public function __invoke(DatabaseReadiness $readiness): Response
    {
        $ready = $readiness->ready();

        return response($ready ? 'Ready' : 'Unavailable', $ready ? 200 : 503)
            ->header('Content-Type', 'text/plain; charset=UTF-8')
            ->header('Cache-Control', 'no-store');
    }
}
