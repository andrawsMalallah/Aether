<?php

use App\Models\User;
use App\Notifications\EmailChangeRequested;
use App\Notifications\ResetAccountPassword;
use App\Notifications\VerifyAccountEmail;
use App\Notifications\VerifyChangedEmail;
use App\Support\Diagnostics\SafeFailedJobProvider;
use App\Support\Diagnostics\SafeQueueWorkCommand;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Notifications\Dispatcher;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Notifications\SendQueuedNotifications;
use Illuminate\Queue\Console\WorkCommand;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Context;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Queue;
use League\OAuth2\Server\Exception\OAuthServerException;
use Monolog\Handler\TestHandler;
use Symfony\Component\Console\Output\BufferedOutput;
use Symfony\Component\Mailer\Transport\Smtp\EsmtpTransport;
use Tests\Support\FailingDiagnosticsJob;

uses(RefreshDatabase::class);

function diagnosticCapture(string $channel = 'diagnostic-test'): TestHandler
{
    config(['logging.channels.'.$channel => ['driver' => 'monolog', 'handler' => TestHandler::class, 'level' => 'debug']]);
    $logger = Log::channel($channel)->getLogger();

    return $logger->getHandlers()[0];
}

function diagnosticPayload(SendQueuedNotifications $job): string
{
    // Only this synthetic job bypasses the test harness's outer transaction.
    $identifier = Queue::connection('database')->push($job->beforeCommit());

    return DB::table('jobs')->where('id', $identifier)->value('payload');
}

it('removes exception messages previous chains arguments shared context and log events across channels', function (string $channel): void {
    $capture = diagnosticCapture($channel);
    config(['logging.default' => $channel]);
    $events = [];
    Event::listen(MessageLogged::class, function (MessageLogged $event) use (&$events): void {
        $events[] = [$event->message, $event->context];
    });
    Context::add('credential', 'diagnostic-sentinel');
    Log::shareContext(['Authorization' => 'Bearer diagnostic-sentinel']);
    Log::withContext(['nested' => ['password' => 'diagnostic-sentinel']]);
    $exception = new QueryException('testing', 'insert into users (password) values (?)', ['diagnostic-sentinel'], new RuntimeException('driver diagnostic-sentinel'));

    app(ExceptionHandler::class)->report($exception);
    Log::warning('https://example.test/reset-password/diagnostic-sentinel', ['nested' => ['token' => 'diagnostic-sentinel']]);

    $records = $capture->getRecords();
    expect(json_encode([$records, $events]))->not->toContain('diagnostic-sentinel', 'insert into users', 'Authorization')
        ->and($records[0]->context['exception_class'])->toBe(QueryException::class)
        ->and($records[0]->context['file'])->toBe(__FILE__)
        ->and($records[0]->context['line'])->toBeInt()
        ->and($records[0]->context['frames'])->toBeArray()
        ->and($records[0]->level->getName())->toBe('ERROR')
        ->and($records[1]->level->getName())->toBe('WARNING');
})->with(['single-equivalent', 'stderr-equivalent']);

it('preserves exception severity and suppression while keeping HTTP errors safe', function (): void {
    $capture = diagnosticCapture();
    config(['logging.default' => 'diagnostic-test']);
    $handler = app(ExceptionHandler::class);
    $handler->level(RuntimeException::class, 'critical');
    $handler->report(new RuntimeException('diagnostic-sentinel'));
    $handler->report(OAuthServerException::invalidRequest('diagnostic-sentinel'));
    expect($capture->getRecords())->toHaveCount(1)
        ->and($capture->getRecords()[0]->level->getName())->toBe('CRITICAL');
    $this->get('/missing-diagnostic-route')->assertNotFound()->assertDontSee('diagnostic-sentinel');
});

it('uses native database exception binding masking on actual query failures', function (): void {
    try {
        DB::insert('insert into missing_diagnostic_table (value) values (?)', ['diagnostic-sentinel']);
        $this->fail('Expected a query failure.');
    } catch (QueryException $exception) {
        expect($exception->getMessage())->toContain('values (?)')->not->toContain('diagnostic-sentinel');
    }
});

it('does not flash credential aliases when normal form validation fails', function (): void {
    $credentials = array_fill_keys(['password', 'password_confirmation', 'current_password', 'code', 'recovery_code', 'client_secret', 'code_verifier', 'refresh_token', 'access_token', 'id_token', 'token', 'auth_token'], 'diagnostic-sentinel');
    $this->from('/login')->post('/login', ['email' => 'invalid-email'] + $credentials)
        ->assertRedirect('/login')->assertSessionHasErrors('email');
    expect(json_encode(session('_old_input')))->not->toContain('diagnostic-sentinel');
});

it('encrypts real notification payloads and still processes each notification', function (string $kind): void {
    $user = User::factory()->create();
    $notification = match ($kind) {
        'reset' => new ResetAccountPassword('diagnostic-sentinel'),
        'verify' => new VerifyAccountEmail,
        'changed' => new VerifyChangedEmail($user->id, 'diagnostic-sentinel@example.test', now()->toImmutable()->addHour()),
        'requested' => new EmailChangeRequested('diagnostic-sentinel@example.test'),
    };
    $job = new SendQueuedNotifications($user, $notification, ['mail']);
    $payload = diagnosticPayload($job);
    expect($payload)->not->toContain('diagnostic-sentinel', $user->email)
        ->and($notification->afterCommit)->toBeTrue();
    $data = json_decode($payload, true);
    $decoded = unserialize(app('encrypter')->decrypt($data['data']['command']));
    expect($decoded)->toBeInstanceOf(SendQueuedNotifications::class)
        ->and($decoded->notification)->toBeInstanceOf($notification::class);
    $decoded->handle(app(Dispatcher::class));
    expect(Mail::mailer('array')->getSymfonyTransport()->messages())->toHaveCount(1);
})->with(['reset', 'verify', 'changed', 'requested']);

it('does not persist encrypted notifications before their transaction commits', function (): void {
    config(['queue.default' => 'database']);
    $user = User::factory()->create();
    $count = DB::table('jobs')->count();
    DB::beginTransaction();
    $user->notify(new ResetAccountPassword('diagnostic-sentinel'));
    expect(DB::table('jobs')->count())->toBe($count);
    DB::rollBack();
    expect(DB::table('jobs')->count())->toBe($count);
});

it('stores safe failed diagnostics without changing encrypted retry payloads or lookup semantics', function (): void {
    $user = User::factory()->create();
    $payload = diagnosticPayload(new SendQueuedNotifications($user, new ResetAccountPassword('diagnostic-sentinel'), ['mail']));
    $provider = app('queue.failer');
    expect($provider)->toBeInstanceOf(SafeFailedJobProvider::class);
    $uuid = $provider->log('database', 'default', $payload, new RuntimeException('diagnostic-sentinel', 0, new RuntimeException('nested diagnostic-sentinel')));
    $failure = $provider->find($uuid);
    expect($failure->payload)->toBe($payload)
        ->and($failure->exception)->not->toContain('diagnostic-sentinel')
        ->and(json_decode($failure->exception, true)['exception_class'])->toBe(RuntimeException::class)
        ->and($provider->ids())->toContain($uuid)
        ->and($provider->count())->toBe(1);
    $job = unserialize(app('encrypter')->decrypt(json_decode($failure->payload, true)['data']['command']));
    expect($job->notification->token)->toBe('diagnostic-sentinel');
    expect($provider->forget($uuid))->toBeTrue()->and($provider->find($uuid))->toBeNull();
});

it('renders console exceptions safely even at debug verbosity', function (): void {
    $output = new BufferedOutput(BufferedOutput::VERBOSITY_DEBUG);
    app(ExceptionHandler::class)->renderForConsole($output, new RuntimeException('diagnostic-sentinel', 0, new RuntimeException('diagnostic-sentinel')));
    $rendered = $output->fetch();
    expect($rendered)->not->toContain('diagnostic-sentinel')->toContain(RuntimeException::class, 'frames', 'line');
});

it('keeps worker json safe without changing retries failure callbacks or retry commands', function (): void {
    $capture = diagnosticCapture();
    config(['logging.default' => 'diagnostic-test']);
    expect(app(WorkCommand::class))->toBeInstanceOf(SafeQueueWorkCommand::class);
    // The framework flag spans test applications; scope this worker's listeners to this application.
    $listeners = new ReflectionProperty(WorkCommand::class, 'hasRegisteredListeners');
    $previous = $listeners->getValue();
    $listeners->setValue(null, false);
    FailingDiagnosticsJob::$failureMessage = null;
    try {
        Queue::connection('database')->push(new FailingDiagnosticsJob, '', 'diagnostics-only');
        $output = new BufferedOutput;
        $options = ['connection' => 'database', '--queue' => 'diagnostics-only', '--once' => true, '--tries' => 2, '--backoff' => 0, '--timeout' => 0, '--json' => true];
        expect(Artisan::call('queue:work', $options, $output))->toBe(0)
            ->and(DB::table('jobs')->count())->toBe(1)
            ->and(DB::table('failed_jobs')->count())->toBe(0);
        expect(Artisan::call('queue:work', $options, $output))->toBe(0)
            ->and(DB::table('jobs')->count())->toBe(0)
            ->and(FailingDiagnosticsJob::$failureMessage)->toBe('worker-diagnostic-sentinel');
        $failure = DB::table('failed_jobs')->sole();
        expect($failure->exception)->not->toContain('worker-diagnostic-sentinel')
            ->and(json_decode($failure->exception, true)['exception_class'])->toBe(RuntimeException::class);
        $rendered = $output->fetch();
        expect($rendered)->toContain('released_after_exception', 'failed', 'exception_class')
            ->not->toContain('worker-diagnostic-sentinel');
        expect(json_encode($capture->getRecords()))->not->toContain('worker-diagnostic-sentinel');
        $command = json_decode($failure->payload, true)['data']['command'];
        expect(Artisan::call('queue:retry', ['id' => [$failure->uuid]]))->toBe(0)
            ->and(DB::table('failed_jobs')->count())->toBe(0)
            ->and(DB::table('jobs')->count())->toBe(1)
            ->and(json_decode(DB::table('jobs')->sole()->payload, true)['data']['command'])->toBe($command);
    } finally {
        $listeners->setValue(null, $previous);
        FailingDiagnosticsJob::$failureMessage = null;
    }
});

it('sanitizes stack records and emergency logger creation failures', function (): void {
    $capture = diagnosticCapture();
    config(['logging.channels.diagnostic-stack' => ['driver' => 'stack', 'channels' => ['diagnostic-test']]]);
    Log::channel('diagnostic-stack')->error('diagnostic-sentinel', ['exception' => new RuntimeException('diagnostic-sentinel')]);
    expect(json_encode($capture->getRecords()))->not->toContain('diagnostic-sentinel')
        ->and($capture->getRecords()[0]->context['exception_class'])->toBe(RuntimeException::class);
    // php://memory keeps fallback output private and avoids touching existing logs.
    config(['logging.channels.emergency.path' => 'php://memory', 'logging.channels.broken' => ['driver' => 'diagnostic-sentinel']]);
    $events = [];
    Event::listen(MessageLogged::class, function (MessageLogged $event) use (&$events): void {
        $events[] = [$event->message, $event->context];
    });
    $fallback = Log::channel('broken');
    $fallback->error('diagnostic-sentinel', ['exception' => new RuntimeException('diagnostic-sentinel')]);
    $stream = $fallback->getLogger()->getHandlers()[0]->getStream();
    rewind($stream);
    expect(stream_get_contents($stream))->not->toContain('diagnostic-sentinel')
        ->and(json_encode($events))->not->toContain('diagnostic-sentinel');
});

it('rejects named and nested log mail outside local and testing while allowing smtp', function (string $environment): void {
    app()->instance('env', $environment);
    config(['mail.mailers.nested' => ['transport' => 'failover', 'mailers' => ['smtp', 'log']]]);
    $manager = app('mail.manager');
    expect(fn () => $manager->mailer('log'))->toThrow(RuntimeException::class, 'Mail body logging is forbidden')
        ->and(fn () => $manager->mailer('nested'))->toThrow(RuntimeException::class, 'Mail body logging is forbidden');
    expect($manager->mailer('smtp')->getSymfonyTransport())->toBeInstanceOf(EsmtpTransport::class);
})->with(['production', 'staging']);

it('keeps explicit local log mail in its separate channel', function (): void {
    $capture = diagnosticCapture('local-mail');
    Mail::mailer('log')->raw('local-mail-sentinel', fn ($message) => $message->to('fake@example.test')->subject('Synthetic mail'));
    expect($capture->getRecords())->toHaveCount(1)
        ->and($capture->getRecords()[0]->message)->toContain('local-mail-sentinel');
});
