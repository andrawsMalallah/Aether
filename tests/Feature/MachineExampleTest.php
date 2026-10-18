<?php

use App\Console\Commands\ReadAetherStats;
use Illuminate\Contracts\Console\Kernel;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;

require_once __DIR__.'/../../resources/examples/machine/ReadAetherStats.php';

beforeEach(function (): void {
    config(['aether-machine' => [
        'issuer' => 'https://identity.example', 'resource_url' => 'https://notes.example/api/stats',
        'client_id' => 'example-machine', 'client_secret' => 'disposable-machine-secret',
    ]]);
    app(Kernel::class)->registerCommand(app(ReadAetherStats::class));
    Http::preventStrayRequests();
});

function exampleMachineToken(array $overrides = []): array
{
    return array_replace([
        'access_token' => 'disposable-machine-token', 'token_type' => 'Bearer',
        'scope' => 'stats:read', 'expires_in' => 300,
    ], $overrides);
}

it('requests a limited machine token calls the resource and revokes before reporting', function (): void {
    Http::fake([
        'identity.example/oauth/token' => Http::response(exampleMachineToken()),
        'notes.example/api/stats' => Http::response(['notes' => 12]),
        'identity.example/oauth/revoke' => Http::response('', 200),
    ]);
    $this->artisan('aether:stats')->expectsOutput('Notes: 12. Temporary token revoked.')->assertSuccessful();
    Http::assertSent(fn ($request): bool => $request->url() === 'https://identity.example/oauth/token'
        && $request['grant_type'] === 'client_credentials' && $request['scope'] === 'stats:read'
        && $request['client_secret'] === 'disposable-machine-secret');
    Http::assertSent(fn ($request): bool => $request->url() === 'https://notes.example/api/stats'
        && $request->hasHeader('Authorization', 'Bearer disposable-machine-token')
        && ! str_contains($request->url(), 'disposable-machine-token'));
    Http::assertSent(fn ($request): bool => $request->url() === 'https://identity.example/oauth/revoke'
        && $request['token'] === 'disposable-machine-token' && $request['token_type_hint'] === 'access_token');
    Http::assertSentCount(3);
});

it('fails safely without calling the resource when issuance is denied or unavailable', function (bool $transportFailure): void {
    Http::fake(function () use ($transportFailure) {
        if ($transportFailure) {
            throw new ConnectionException('unsafe transport detail');
        }

        return Http::response(['error' => 'unsafe upstream detail'], 401);
    });
    $this->artisan('aether:stats')
        ->expectsOutput('Token request failed. Check availability, administrator approval and resource access.')
        ->doesntExpectOutputToContain('unsafe')->doesntExpectOutputToContain('Notes:')->assertFailed();
    Http::assertNotSent(fn ($request): bool => $request->url() === 'https://notes.example/api/stats');
})->with([false, true]);

it('cleans a received token even when the token response is malformed', function (array $overrides): void {
    Http::fake([
        'identity.example/oauth/token' => Http::response(exampleMachineToken($overrides)),
        'identity.example/oauth/revoke' => Http::response('', 200),
    ]);
    $this->artisan('aether:stats')->doesntExpectOutputToContain('Notes:')->assertFailed();
    Http::assertSent(fn ($request): bool => str_ends_with($request->url(), '/oauth/revoke'));
    Http::assertSentCount(2);
})->with([
    [['token_type' => ['Bearer']]], [['token_type' => 'Basic']], [['scope' => 'other:scope']],
    [['expires_in' => '300']], [['expires_in' => 0]], [['id_token' => null]], [['refresh_token' => 'unexpected']],
]);

it('revokes after denied unavailable redirected or malformed resource responses', function (int $status, array $body): void {
    Http::fake([
        'identity.example/oauth/token' => Http::response(exampleMachineToken()),
        'notes.example/api/stats' => Http::response($body, $status),
        'identity.example/oauth/revoke' => Http::response('', 200),
    ]);
    $this->artisan('aether:stats')
        ->expectsOutput('Approved resource request failed. Check availability, administrator approval and resource access.')
        ->doesntExpectOutputToContain('Notes:')->assertFailed();
    Http::assertSent(fn ($request): bool => str_ends_with($request->url(), '/oauth/revoke'));
    Http::assertSentCount(3);
})->with([
    [401, ['error' => 'unsafe']], [403, ['error' => 'unsafe']], [503, ['error' => 'unsafe']],
    [302, []], [200, ['notes' => -1]], [200, ['notes' => '12']], [200, ['notes' => 12, 'private' => 'unsafe']],
]);

it('withholds the report if cleanup cannot be confirmed', function (): void {
    Http::fake([
        'identity.example/oauth/token' => Http::response(exampleMachineToken()),
        'notes.example/api/stats' => Http::response(['notes' => 12]),
        'identity.example/oauth/revoke' => Http::response('unsafe upstream detail', 503),
    ]);
    $this->artisan('aether:stats')
        ->expectsOutput('Token cleanup could not be confirmed. No report was printed. Ask the operator to revoke credentials or wait for token expiry.')
        ->doesntExpectOutputToContain('Notes:')->doesntExpectOutputToContain('unsafe')->assertFailed();
});

it('rejects unsafe configured endpoints before sending credentials', function (string $url): void {
    config(['aether-machine.resource_url' => $url]);
    Http::fake();
    $this->artisan('aether:stats')->assertFailed();
    Http::assertNothingSent();
})->with(['http://notes.example/api/stats', 'https://user:password@notes.example/api/stats', 'https://notes.example/api/stats?token=unsafe', 'https://notes.example/api/stats#unsafe']);
