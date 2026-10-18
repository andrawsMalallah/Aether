<?php

use App\Actions\Account\PruneAccountExports;
use Illuminate\Foundation\Inspiring;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Schedule;

Artisan::command('inspire', function () {
    $this->comment(Inspiring::quote());
})->purpose('Display an inspiring quote');

Artisan::command('account-exports:prune', function (PruneAccountExports $prune): void {
    $this->info('Expired account exports removed: '.$prune->handle());
})->purpose('Remove expired generated account export files');

Schedule::command('account-exports:prune')->hourly()->withoutOverlapping();
