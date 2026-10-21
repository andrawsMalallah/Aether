<?php

use App\Actions\Account\PruneAccountExports;
use App\Enums\AccountExportStatus;
use App\Enums\OAuthAuditEvent;
use App\Jobs\FinalizeAccountDeletion;
use App\Jobs\GenerateAccountExport;
use App\Models\AccountExport;
use App\Models\AuditLog;
use App\Models\User;
use App\Services\AccountExportWriter;
use App\Services\PrivateStorage;
use App\Services\RevokeAccountAccess;
use Aws\MockHandler;
use Aws\Result;
use GuzzleHttp\Psr7\Utils;
use Illuminate\Filesystem\AwsS3V3Adapter;
use Illuminate\Filesystem\FilesystemAdapter;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    config(['filesystems.private_disk' => 'private_s3',
        'filesystems.disks.private_s3.key' => 'isolated-test-key',
        'filesystems.disks.private_s3.secret' => 'isolated-test-secret',
        'filesystems.disks.private_s3.bucket' => 'isolated-test-bucket',
        'filesystems.disks.private_s3.region' => 'us-east-1',
        'filesystems.disks.private_s3.endpoint' => 'https://storage.example.test']);
    Storage::fake('private_s3');
    // Any accidental hardcoded local access must fail, rather than quietly pass.
    Storage::set('local', Mockery::mock(FilesystemAdapter::class));
    Notification::fake();
    Queue::fake();
    $this->owner = User::factory()->create();
});

function privateExport(User $owner): AccountExport
{
    return AccountExport::create(['user_id' => $owner->id, 'status' => AccountExportStatus::Pending, 'expires_at' => now()->addDay()]);
}

it('uses the selected private disk for export generation download duplicate delivery and expiry', function (): void {
    $export = privateExport($this->owner);
    $job = new GenerateAccountExport($export->id);
    $job->handle(app(AccountExportWriter::class));
    $expiry = $export->fresh()->expires_at->timestamp;
    $job->handle(app(AccountExportWriter::class));
    expect($export->fresh()->expires_at->timestamp)->toBe($expiry)
        ->and(AuditLog::where('event', OAuthAuditEvent::AccountExported)->count())->toBe(1);
    $this->actingAs($this->owner)->withSession(['auth.password_confirmed_at' => now()->timestamp]);
    $response = $this->get(route('account.export.download', $export));
    $response->assertOk()->assertHeader('Content-Type', 'application/json')->assertHeader('Cache-Control', 'no-store, private');
    expect(json_decode($response->streamedContent(), true, 512, JSON_THROW_ON_ERROR)['profile']['id'])->toBe($this->owner->id);
    $this->actingAs(User::factory()->create())->get(route('account.export.download', $export))->assertForbidden();
    $this->travelTo($export->fresh()->expires_at);
    app(PruneAccountExports::class)->handle();
    expect($export->fresh()->status)->toBe(AccountExportStatus::Expired);
    PrivateStorage::disk()->assertMissing($export->relativePath());
});

it('stores replaces and streams avatars and retains previous logos on the private disk', function (): void {
    $this->actingAs($this->owner);
    $this->put('/account/profile', ['name' => 'Owner', 'avatar' => UploadedFile::fake()->image('avatar.png')])->assertRedirect();
    $old = $this->owner->fresh()->avatar_path;
    $this->put('/account/profile', ['name' => 'Owner', 'avatar' => UploadedFile::fake()->image('replacement.png')])->assertRedirect();
    PrivateStorage::disk()->assertMissing($old);
    $response = $this->get('/account/avatar')->assertOk();
    expect($response->streamedContent())->not->toBeEmpty();
    $this->owner->forceFill(['is_developer' => true])->save();
    $this->actingAs($this->owner->fresh());
    $client = oauthClientFixture($this->owner, true);
    $settings = ['name' => 'Private logo', 'redirect_urls' => 'https://example.com/callback', 'scopes' => ['openid']];
    $this->put(route('developer.apps.update', $client), $settings + ['logo' => UploadedFile::fake()->image('logo.png')])->assertRedirect(route('developer.apps.show', $client))->assertSessionHasNoErrors();
    $oldLogo = $client->fresh()->logo_path;
    expect($oldLogo)->toBeString();
    $this->put(route('developer.apps.update', $client), $settings + ['logo' => UploadedFile::fake()->image('new.png')])->assertSessionHasNoErrors();
    PrivateStorage::disk()->assertExists($oldLogo);
    $response = $this->get(route('passport.client.logo', $client))->assertOk()->assertHeader('X-Content-Type-Options', 'nosniff');
    expect($response->streamedContent())->not->toBeEmpty();
});

it('cleans private account artifacts while preserving other owners files', function (): void {
    config(['session.driver' => 'database', 'session.connection' => null]);
    $export = privateExport($this->owner);
    PrivateStorage::disk()->put($export->relativePath(), 'export');
    PrivateStorage::disk()->put('avatars/test.png', 'avatar');
    PrivateStorage::disk()->put('avatars/other.png', 'other');
    $this->owner->forceFill(['avatar_path' => 'avatars/test.png', 'deletion_requested_at' => now()->subDays(15), 'deletion_due_at' => now()->subDay()])->save();
    $job = new FinalizeAccountDeletion($this->owner->id);
    $job->handle(app(RevokeAccountAccess::class));
    $job->handle(app(RevokeAccountAccess::class));
    PrivateStorage::disk()->assertMissing([$export->relativePath(), 'avatars/test.png']);
    PrivateStorage::disk()->assertExists('avatars/other.png');
    expect($this->owner->fresh()->anonymized_at)->not->toBeNull();
});

it('never marks a failed stream upload ready and closes its temporary stream', function (bool $throws): void {
    $export = privateExport($this->owner);
    $disk = Mockery::mock(FilesystemAdapter::class);
    $captured = null;
    $disk->shouldReceive('put')->once()->withArgs(function ($path, $stream, $options) use ($export, &$captured): bool {
        $captured = $stream;
        expect(is_resource($stream))->toBeTrue();
        expect(json_decode(stream_get_contents($stream), true)['profile']['id'])->toBe($this->owner->id);

        return $path === $export->relativePath() && $options['visibility'] === 'private';
    })->andReturnUsing(function () use ($throws): bool {
        if ($throws) {
            throw new RuntimeException('Synthetic upload failure');
        }

        return false;
    });
    $disk->shouldReceive('delete')->once()->with([$export->relativePath(), $export->relativePath().'.partial'])->andReturn(true);
    Storage::set('private_s3', $disk);
    expect(fn () => (new GenerateAccountExport($export->id))->handle(app(AccountExportWriter::class)))->toThrow(RuntimeException::class);
    expect(is_resource($captured))->toBeFalse()->and($export->fresh()->status)->toBe(AccountExportStatus::Pending)->and(AuditLog::count())->toBe(0);
    Notification::assertNothingSent();
})->with([false, true]);

it('removes a private upload on audit rollback and safely retries', function (): void {
    $export = privateExport($this->owner);
    AuditLog::creating(fn () => throw new RuntimeException('Synthetic audit failure'));
    try {
        expect(fn () => (new GenerateAccountExport($export->id))->handle(app(AccountExportWriter::class)))->toThrow(RuntimeException::class);
        PrivateStorage::disk()->assertMissing($export->relativePath());
        expect($export->fresh()->status)->toBe(AccountExportStatus::Pending);
    } finally {
        AuditLog::flushEventListeners();
    }
    (new GenerateAccountExport($export->id))->handle(app(AccountExportWriter::class));
    expect($export->fresh()->available())->toBeTrue();
});

it('fails before returning download headers if a private stream cannot be opened', function (): void {
    $disk = Mockery::mock(FilesystemAdapter::class);
    $disk->shouldReceive('readStream')->with('known-private-file')->once()->andReturn(false);
    Storage::set('private_s3', $disk);
    expect(fn () => PrivateStorage::response('known-private-file', 'application/json', []))->toThrow(RuntimeException::class);
});

it('closes scratch data after writer failure without uploading or changing readiness', function (): void {
    $export = privateExport($this->owner);
    $captured = null;
    $writer = Mockery::mock(AccountExportWriter::class);
    $writer->shouldReceive('write')->once()->andReturnUsing(function ($owner, $stream) use (&$captured): void {
        $captured = $stream;
        fwrite($stream, 'incomplete');
        throw new RuntimeException('Synthetic scratch write failure');
    });
    expect(fn () => (new GenerateAccountExport($export->id))->handle($writer))->toThrow(RuntimeException::class);
    expect(is_resource($captured))->toBeFalse()->and($export->fresh()->status)->toBe(AccountExportStatus::Pending);
    expect(PrivateStorage::disk()->allFiles())->toBe([]);
    Notification::assertNothingSent();
});

it('retries notification without reuploading or extending private export expiry', function (): void {
    $export = privateExport($this->owner);
    Notification::shouldReceive('send')->once()->andThrow(new RuntimeException('Synthetic queue failure'));
    expect(fn () => (new GenerateAccountExport($export->id))->handle(app(AccountExportWriter::class)))->toThrow(RuntimeException::class);
    $expiry = $export->fresh()->expires_at->timestamp;
    expect($export->fresh()->status)->toBe(AccountExportStatus::ReadyToNotify);
    PrivateStorage::disk()->assertExists($export->relativePath());
    Notification::fake();
    $writer = Mockery::mock(AccountExportWriter::class);
    $writer->shouldNotReceive('write');
    (new GenerateAccountExport($export->id))->handle($writer);
    expect($export->fresh()->status)->toBe(AccountExportStatus::Ready)->and($export->fresh()->expires_at->timestamp)->toBe($expiry);
});

it('does not finalize accounts or exhausted jobs when private artifact cleanup fails', function (): void {
    config(['session.driver' => 'database', 'session.connection' => null]);
    $export = privateExport($this->owner);
    $this->owner->forceFill(['deletion_requested_at' => now()->subDays(15), 'deletion_due_at' => now()->subDay()])->save();
    $disk = Mockery::mock(FilesystemAdapter::class);
    $disk->shouldReceive('delete')->twice()->with([$export->relativePath(), $export->relativePath().'.partial'])->andReturn(false);
    Storage::set('private_s3', $disk);
    expect(fn () => (new FinalizeAccountDeletion($this->owner->id))->handle(app(RevokeAccountAccess::class)))->toThrow(RuntimeException::class);
    expect(fn () => (new GenerateAccountExport($export->id))->failed(null))->toThrow(RuntimeException::class);
    expect($this->owner->fresh()->anonymized_at)->toBeNull()->and($export->fresh()->status)->toBe(AccountExportStatus::Pending)
        ->and(AuditLog::where('event', OAuthAuditEvent::AccountDeleted)->count())->toBe(0);
});

it('keeps failed cleanup retryable without claiming expiry or anonymization', function (bool $throws): void {
    $export = privateExport($this->owner);
    $export->update(['expires_at' => now()->subSecond()]);
    $disk = Mockery::mock(FilesystemAdapter::class);
    $expectation = $disk->shouldReceive('delete')->once()->with([$export->relativePath(), $export->relativePath().'.partial']);
    $throws ? $expectation->andThrow(new RuntimeException('Synthetic delete failure')) : $expectation->andReturn(false);
    Storage::set('private_s3', $disk);
    if ($throws) {
        expect(fn () => app(PruneAccountExports::class)->handle())->toThrow(RuntimeException::class);
    } else {
        expect(app(PruneAccountExports::class)->handle())->toBe(0);
    }
    expect($export->fresh()->status)->toBe(AccountExportStatus::Pending);
})->with([false, true]);

it('rejects public unknown incomplete or insecure storage configuration', function (string $setting): void {
    match ($setting) {
        'public' => config(['filesystems.private_disk' => 'public']),
        'unknown' => config(['filesystems.private_disk' => 'missing']),
        'incomplete' => config(['filesystems.disks.private_s3.bucket' => '']),
        'http' => config(['filesystems.disks.private_s3.endpoint' => 'http://storage.example.test']),
        'visibility' => config(['filesystems.disks.private_s3.visibility' => 'public']),
    };
    expect(fn () => PrivateStorage::disk())->toThrow(RuntimeException::class);
})->with(['public', 'unknown', 'incomplete', 'http', 'visibility']);

it('instantiates the real S3 adapter and uploads a private stream without network access', function (): void {
    Storage::forgetDisk('private_s3');
    $handler = new MockHandler;
    $handler->append(new Result(['ETag' => 'synthetic-etag']));
    config(['filesystems.disks.private_s3.handler' => $handler]);
    $disk = PrivateStorage::disk();
    expect($disk)->toBeInstanceOf(AwsS3V3Adapter::class);
    $stream = tmpfile();
    try {
        fwrite($stream, '{"isolated":true}');
        rewind($stream);
        expect($disk->put('account-exports/test.json', $stream, ['visibility' => 'private']))->toBeTrue();
        $command = $handler->getLastCommand();
        expect($command->getName())->toBe('PutObject')->and($command['Bucket'])->toBe('isolated-test-bucket')
            ->and($command['Key'])->toBe('aether/account-exports/test.json')->and($command['ACL'])->toBe('private');
        expect((string) $command['Body'])->toBe('{"isolated":true}');
        $handler->append(new Result(['Body' => Utils::streamFor('private content')]));
        $response = PrivateStorage::response('account-exports/test.json', 'application/json', ['Cache-Control' => 'no-store, private']);
        $command = $handler->getLastCommand();
        expect($command->getName())->toBe('GetObject')->and($command['@http']['stream'])->toBeTrue();
        ob_start();
        $response->sendContent();
        expect(ob_get_clean())->toBe('private content');
        $handler->append(new Result);
        expect($disk->delete('account-exports/test.json'))->toBeTrue();
        expect($handler->getLastCommand()->getName())->toBe('DeleteObject');
        $handler->append(new Result(['ETag' => 'synthetic-image-etag']));
        $image = UploadedFile::fake()->image('avatar.png');
        expect($image->store('avatars', PrivateStorage::name()))->toStartWith('avatars/');
        expect($handler->getLastCommand()['ACL'])->toBe('private');
    } finally {
        fclose($stream);
    }
});
