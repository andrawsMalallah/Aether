<?php

use App\Jobs\RevokeAetherExampleToken;
use Illuminate\Contracts\Bus\Dispatcher;
use Illuminate\Contracts\Queue\ShouldBeEncrypted;
use Illuminate\Support\Facades\Blade;
use Illuminate\Support\Facades\Bus;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\ViewErrorBag;
use Laravel\Socialite\Facades\Socialite;

class ExampleSocialiteFacade extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'example.socialite';
    }
}

beforeAll(function (): void {
    // Execute the displayed code so the guide cannot silently drift from these checks.
    $source = file_get_contents(__DIR__.'/../../resources/views/developer/laravel-example.blade.php');
    preg_match_all('/\$(\w+) = <<<\'PHP\'\R(.*?)\RPHP;/s', $source, $matches, PREG_SET_ORDER);
    foreach ($matches as $match) {
        if (in_array($match[1], ['requestExample', 'jobExample', 'controllerExample'], true)) {
            eval(substr($match[2], strlen('<?php')));
        }
    }
    // Aether does not install a client SDK; substitute only that external boundary.
    if (! class_exists(Socialite::class)) {
        class_alias(ExampleSocialiteFacade::class, Socialite::class);
    }
});

beforeEach(function (): void {
    config(['oidc.connections.aether' => [
        'base_url' => 'https://identity.example',
        'client_id' => 'example-client',
        'client_secret' => 'disposable-example-secret',
    ]]);
    ExampleSocialiteFacade::clearResolvedInstances();
    $this->socialite = Mockery::mock();
    app()->instance('example.socialite', $this->socialite);
    $this->provider = Mockery::mock();
    Bus::fake();

    $source = file_get_contents(resource_path('views/developer/laravel-example.blade.php'));
    preg_match('/\$routesExample = <<<\'PHP\'\R(.*?)\RPHP;/s', $source, $matches);
    Route::middleware('web')->group(function () use ($matches): void {
        eval(substr($matches[1], strlen('<?php')));
    });
});

it('starts a bounded stateful attempt using the library redirect', function (): void {
    $this->socialite->shouldReceive('driver')->once()->with('oidc_aether')->andReturn($this->provider);
    $this->provider->shouldReceive('redirect')->once()->andReturn(redirect('https://identity.example/oauth/authorize'));

    $this->get('/auth/aether')->assertRedirect('https://identity.example/oauth/authorize')
        ->assertSessionHas('aether_attempt_expires', fn (int $expiry): bool => $expiry > time() && $expiry <= time() + 300);
});

it('establishes only a short identity session and queues encrypted cleanup after validation', function (): void {
    $identity = Mockery::mock();
    $identity->token = 'disposable-example-access-token';
    $identity->shouldReceive('getRaw')->once()->andReturn(['iss' => 'https://identity.example', 'sub' => 'subject-1']);
    $this->socialite->shouldReceive('driver')->once()->with('oidc_aether')->andReturn($this->provider);
    $this->provider->shouldReceive('user')->once()->andReturn($identity);

    $this->withSession(['aether_attempt_expires' => time() + 300, 'state' => 'attempt-state'])
        ->get('/auth/aether/callback?state=attempt-state&code=disposable-code')
        ->assertRedirect('/aether-example')
        ->assertSessionHas('aether_example.subject', 'subject-1')
        ->assertSessionHas('aether_example.issuer', 'https://identity.example')
        ->assertSessionMissing('state')->assertSessionMissing('aether_attempt_expires');

    Bus::assertDispatched(RevokeAetherExampleToken::class);
    expect(session('aether_example'))->toHaveKeys(['issuer', 'subject', 'expires_at'])
        ->and(session('aether_example.expires_at'))->toBeLessThanOrEqual(time() + 900);

    $this->get('/auth/aether/callback?state=attempt-state&code=disposable-code')
        ->assertSessionHasErrors('login')->assertSessionMissing('aether_example');
});

it('rejects denied expired and malformed callbacks without leaking input or calling the SDK', function (): void {
    $this->withSession(['aether_attempt_expires' => time() + 300, 'code_verifier' => 'disposable-verifier'])
        ->get('/auth/aether/callback?state=attempt-state&error=access_denied')
        ->assertRedirect('/aether-example')->assertSessionHasErrors('login')->assertSessionMissing('code_verifier');
    $this->withSession(['aether_attempt_expires' => time() - 1])
        ->get('/auth/aether/callback?state=attempt-state&code=disposable-code')
        ->assertSessionHasErrors('login');
    $this->get('/auth/aether/callback?code[]=disposable-code')
        ->assertRedirect('/aether-example')->assertSessionHasErrors('login')->assertSessionMissing('_old_input');
    Bus::assertNothingDispatched();
});

it('clears the local identity on logout', function (): void {
    $this->withSession(['aether_example' => ['issuer' => 'https://identity.example', 'subject' => 'subject-1', 'expires_at' => time() + 900]])
        ->post('/auth/aether/logout')->assertRedirect('/aether-example')->assertSessionMissing('aether_example');
    Bus::assertNothingDispatched();
});

it('revokes with bounded HTTP and discards unsafe response exception context', function (): void {
    Http::preventStrayRequests();
    Http::fake(['identity.example/oauth/revoke' => Http::sequence()->push('', 200)->push('unsafe upstream detail', 503)]);
    $job = new RevokeAetherExampleToken('disposable-example-access-token');
    expect($job)->toBeInstanceOf(ShouldBeEncrypted::class);
    $job->handle();
    Http::assertSent(fn ($request): bool => $request->url() === 'https://identity.example/oauth/revoke'
        && $request['token'] === 'disposable-example-access-token'
        && $request['token_type_hint'] === 'access_token');

    expect(fn () => $job->handle())->toThrow(RuntimeException::class, 'Aether credential cleanup is unavailable.');
});

it('rejects an unexpected issuer before establishing identity or dispatching cleanup', function (): void {
    $identity = Mockery::mock();
    $identity->shouldReceive('getRaw')->andReturn(['iss' => 'https://unexpected.example', 'sub' => 'subject-1']);
    $this->socialite->shouldReceive('driver')->with('oidc_aether')->andReturn($this->provider);
    $this->provider->shouldReceive('user')->andReturn($identity);
    $this->withSession(['aether_attempt_expires' => time() + 300])
        ->get('/auth/aether/callback?state=attempt-state&code=disposable-code')
        ->assertSessionHasErrors('login')->assertSessionMissing('aether_example');
    Bus::assertNothingDispatched();
});

it('renders the example view with escaped identity and a CSRF protected logout form', function (): void {
    $source = file_get_contents(resource_path('views/developer/laravel-example.blade.php'));
    preg_match('/\$viewExample = <<<\'BLADE\'\R(.*?)\RBLADE;/s', $source, $matches);
    $html = Blade::render($matches[1], [
        'identity' => ['subject' => '<script>untrusted</script>', 'issuer' => 'https://identity.example'],
        'errors' => new ViewErrorBag,
    ]);
    expect($html)->toContain('&lt;script&gt;untrusted&lt;/script&gt;', 'name="_token"', 'method="POST"')
        ->not->toContain('<script>untrusted</script>');
});

it('does not establish a session when cleanup cannot be queued', function (): void {
    $identity = Mockery::mock();
    $identity->token = 'disposable-example-access-token';
    $identity->shouldReceive('getRaw')->andReturn(['iss' => 'https://identity.example', 'sub' => 'subject-1']);
    $this->socialite->shouldReceive('driver')->with('oidc_aether')->andReturn($this->provider);
    $this->provider->shouldReceive('user')->andReturn($identity);
    $dispatcher = Mockery::mock(Dispatcher::class);
    $dispatcher->shouldReceive('dispatch')->once()->andThrow(new RuntimeException('Unsafe queue detail'));
    app()->instance(Dispatcher::class, $dispatcher);

    $this->withSession(['aether_attempt_expires' => time() + 300])
        ->get('/auth/aether/callback?state=attempt-state&code=disposable-code')
        ->assertRedirect('/aether-example')->assertSessionHasErrors('login')
        ->assertSessionMissing('aether_example')->assertSessionMissing('aether_attempt_expires');
    expect(session('errors')->first('login'))->not->toContain('Unsafe queue detail');
});
