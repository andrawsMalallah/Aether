<?php

use App\Services\Deployment\DatabaseReadiness;
use Illuminate\Support\Facades\DB;

it('returns fixed public readiness responses with browser protection and no session', function (bool $ready): void {
    $this->mock(DatabaseReadiness::class)->shouldReceive('ready')->once()->andReturn($ready);
    $this->get('/ready')->assertStatus($ready ? 200 : 503)
        ->assertContent($ready ? 'Ready' : 'Unavailable')
        ->assertHeader('Cache-Control', 'no-store, private')
        ->assertHeader('X-Content-Type-Options', 'nosniff')
        ->assertHeader('X-Frame-Options', 'DENY')
        ->assertCookieMissing(config('session.cookie'));
})->with([true, false]);

it('probes the dedicated PostgreSQL test database without mutating records', function (): void {
    expect(app(DatabaseReadiness::class)->ready())->toBeTrue();
});

it('contains readiness connection errors and refuses alternate drivers', function (): void {
    DB::shouldReceive('connection->getConfig')->andReturn(['driver' => 'mysql']);
    expect(app(DatabaseReadiness::class)->ready())->toBeFalse();
});

it('contains readiness bootstrap failures', function (): void {
    DB::shouldReceive('connection')->andThrow(new RuntimeException('sensitive-marker'));
    expect(app(DatabaseReadiness::class)->ready())->toBeFalse();
});

it('renders a fixed readiness response when routing or dependency resolution fails', function (): void {
    $this->mock(DatabaseReadiness::class)->shouldReceive('ready')->andThrow(new RuntimeException('sensitive-marker'));
    $this->get('/ready')->assertStatus(503)->assertContent('Unavailable');
});

it('refuses deployment checks outside the approved production posture without printing configuration', function (): void {
    config(['app.key' => 'sensitive-marker']);
    $this->artisan('deployment:check')->expectsOutput('Deployment configuration is invalid.')->assertFailed();
});
