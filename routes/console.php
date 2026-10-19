<?php

use App\Actions\Account\PruneAccountExports;
use App\Jobs\FinalizeAccountDeletion;
use App\Models\User;
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

Artisan::command('accounts:finalize-deletions', function (): void {
    User::whereNotNull('deletion_requested_at')->where('deletion_due_at', '<=', now())->whereNull('anonymized_at')->select('id')->chunkById(250, function ($users): void {
        foreach ($users as $user) {
            FinalizeAccountDeletion::dispatch($user->id);
        }
    });
    $this->info('Due account deletions queued.');
})->purpose('Queue final erasure for accounts whose deletion grace period has ended');

Schedule::command('accounts:finalize-deletions')->hourly()->withoutOverlapping();
