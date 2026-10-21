<?php

use App\Services\OAuth\ClientRepository;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;

uses(RefreshDatabase::class);

it('uses PostgreSQL and treats malformed client identifiers as missing without invalid UUID queries', function (): void {
    expect(DB::getDriverName())->toBe('pgsql');
    $repository = app(ClientRepository::class);
    foreach (['not-a-client', '', 123] as $identifier) {
        expect($repository->find($identifier))->toBeNull()
            ->and($repository->findActive($identifier))->toBeNull();
    }
});

it('returns protocol authentication errors for malformed basic authentication client identifiers', function (string $path): void {
    $this->withHeaders(['Authorization' => 'Basic '.base64_encode('not-a-uuid:invalid-secret')])
        ->postJson($path, ['token' => 'unknown-token'])
        ->assertUnauthorized()->assertJsonPath('error', 'invalid_client');
})->with(['/oauth/revoke', '/oauth/introspect']);

it('rejects malformed application route identifiers before database binding', function (): void {
    $this->get('/admin/apps/not-a-uuid')->assertNotFound();
    $this->get('/developer/apps/not-a-uuid')->assertNotFound();
});
