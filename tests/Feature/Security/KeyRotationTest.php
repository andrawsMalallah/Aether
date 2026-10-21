<?php

use App\Enums\OAuthAppType;
use App\Enums\OAuthClientStatus;
use App\Jobs\GenerateAccountExport;
use App\Models\OAuthClient;
use App\Models\User;
use App\Services\OAuth\OidcKeys;
use App\Services\OAuth\ReadToken;
use Illuminate\Contracts\Encryption\DecryptException;
use Illuminate\Cookie\Middleware\EncryptCookies;
use Illuminate\Encryption\Encrypter;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Http\Request;
use Illuminate\Queue\CallQueuedHandler;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\Str;
use Laravel\Fortify\Actions\EnableTwoFactorAuthentication;
use Laravel\Fortify\Fortify;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\ResourceServer;
use phpseclib4\Crypt\EC;
use phpseclib4\Crypt\RSA;
use PragmaRX\Google2FA\Google2FA;
use Tests\TestCase;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    $this->freezeTime();
});

/** @return array{private: string, public: string} */
function rotationPair(int $number): array
{
    static $pairs = [];
    if (! isset($pairs[$number])) {
        $key = RSA::createKey(2048);
        $pairs[$number] = ['private' => (string) $key, 'public' => (string) $key->getPublicKey()];
    }

    return $pairs[$number];
}

/** @param array{private: string, public: string} $active
 * @param  list<string>  $additional
 */
function rotationConfigure(array $active, array $additional = []): void
{
    config(['passport.private_key' => $active['private'], 'passport.public_key' => $active['public'],
        'oauth_keys.additional_public_keys' => $additional]);
    app()->forgetInstance(AuthorizationServer::class);
    app()->forgetInstance(ResourceServer::class);
}

/** @return array<string, mixed> */
function rotationIssue(TestCase $test, User $user, OAuthClient $client): array
{
    $parameters = oauthParameters($client, 'openid email');
    $parameters['nonce'] = 'rotation-fixture-nonce';
    $response = $test->actingAs($user)->get(oauthAuthorizeUrl($parameters));
    if ($response->getStatusCode() === 200) {
        $response = $test->post('/oauth/authorize', ['auth_token' => session('authToken')]);
    }
    parse_str(parse_url($response->headers->get('Location'), PHP_URL_QUERY), $callback);

    return $test->postJson('/oauth/token', oauthExchange($client, $callback['code']))->assertOk()->json();
}

/** @param list<string> $previous */
function rotationFrameworkKey(string $key, array $previous = []): void
{
    config(['app.key' => $key, 'app.previous_keys' => $previous]);
    app()->forgetInstance('encrypter');
    Crypt::clearResolvedInstance('encrypter');
    Fortify::encryptUsing(null);
    app()->forgetInstance(AuthorizationServer::class);
}

it('supports prepublication promotion rollback and public retirement without changing token formats', function (bool $confidential): void {
    $old = ['private' => config('passport.private_key'), 'public' => config('passport.public_key')];
    $next = rotationPair(1);
    $user = User::factory()->create();
    $client = oauthClientFixture(confidential: $confidential);
    $original = rotationIssue($this, $user, $client);
    $parser = new Parser(new JoseEncoder);
    $oldId = $parser->parse($original['id_token']);
    expect($parser->parse($original['access_token'])->headers()->has('kid'))->toBeFalse();
    rotationConfigure($old, [$next['public']]);
    $prepublished = $this->getJson('/.well-known/jwks.json')->assertOk()->assertHeader('Cache-Control', 'no-store, private')->json('keys');
    expect($prepublished)->toHaveCount(2)->and($prepublished[0]['kid'])->toBe($oldId->headers()->get('kid'));
    rotationConfigure($next, [$old['public']]);
    $new = rotationIssue($this, $user, $client);
    $newId = $parser->parse($new['id_token']);
    expect($newId->headers()->get('kid') !== $oldId->headers()->get('kid'))->toBeTrue();
    foreach (['iss', 'aud', 'sub', 'nonce', 'auth_time'] as $claim) {
        expect($newId->claims()->get($claim))->toBe($oldId->claims()->get($claim));
    }
    expect((new Validator)->validate($oldId, new SignedWith(new Sha256, InMemory::plainText($old['public']))))->toBeTrue();
    expect((new Validator)->validate($newId, new SignedWith(new Sha256, InMemory::plainText($next['public']))))->toBeTrue();
    $published = $this->getJson('/.well-known/jwks.json')->assertOk()->json('keys');
    foreach ([$original, $new] as $pair) {
        $identity = $parser->parse($pair['id_token']);
        $jwk = collect($published)->firstWhere('kid', $identity->headers()->get('kid'));
        $verificationKey = RSA::loadPublicKeyFormat('JWK', json_encode(['keys' => [$jwk]], JSON_THROW_ON_ERROR));
        $segments = explode('.', $pair['id_token']);
        expect($verificationKey->withPadding(RSA::SIGNATURE_PKCS1)->withHash('sha256')
            ->verify($segments[0].'.'.$segments[1], base64_decode(strtr($segments[2], '-_', '+/'))))->toBeTrue();
        $this->withToken($pair['access_token'])->getJson('/oauth/userinfo')->assertOk()->assertJsonPath('sub', (string) $user->id);
    }
    rotationConfigure($old, [$next['public']]);
    expect(oauthBearerWorks($original['access_token']))->toBeTrue()->and(oauthBearerWorks($new['access_token']))->toBeTrue();
    rotationConfigure($next);
    expect(oauthBearerWorks($original['access_token']))->toBeFalse()->and(oauthBearerWorks($new['access_token']))->toBeTrue();
    $this->getJson('/.well-known/jwks.json')->assertOk()->assertJsonCount(1, 'keys')->assertJsonPath('keys.0.kid', $newId->headers()->get('kid'));
})->with([false, true]);

it('continues refreshing and revoking an old pair during RSA overlap with pair scoping intact', function (): void {
    $oldPublic = config('passport.public_key');
    $client = oauthClientFixture(confidential: true);
    $user = User::factory()->create();
    $original = rotationIssue($this, $user, $client);
    $independent = rotationIssue($this, $user, $client);
    rotationConfigure(rotationPair(1), [$oldPublic]);
    $successor = $this->postJson('/oauth/token', ['grant_type' => 'refresh_token', 'client_id' => $client->id,
        'client_secret' => $client->plainSecret, 'refresh_token' => $original['refresh_token']])->assertOk()->json();
    $this->post('/oauth/revoke', ['client_id' => $client->id, 'client_secret' => $client->plainSecret, 'token' => $original['access_token']])->assertOk()->assertContent('');
    expect(oauthBearerWorks($successor['access_token']))->toBeTrue()->and(oauthBearerWorks($independent['access_token']))->toBeTrue();
    $foreign = oauthClientFixture();
    $this->post('/oauth/revoke', ['client_id' => $foreign->id, 'token' => $independent['access_token']])->assertOk()->assertContent('');
    expect(oauthBearerWorks($independent['access_token']))->toBeTrue();
    $this->post('/oauth/revoke', ['client_id' => $client->id, 'client_secret' => $client->plainSecret, 'token' => $independent['access_token']])->assertOk()->assertContent('');
    expect(oauthBearerWorks($independent['access_token']))->toBeFalse();
});

it('does not revive a revoked token or trust an outsider signature during overlap', function (): void {
    $old = ['private' => config('passport.private_key'), 'public' => config('passport.public_key')];
    $client = oauthClientFixture();
    $original = rotationIssue($this, User::factory()->create(), $client);
    rotationConfigure(rotationPair(1), [$old['public']]);
    Passport::token()->newQuery()->update(['revoked' => true]);
    expect(oauthBearerWorks($original['access_token']))->toBeFalse();
    Passport::token()->newQuery()->update(['revoked' => false]);
    $stored = Passport::token()->newQuery()->sole();
    $outsider = rotationPair(2);
    $configuration = Configuration::forAsymmetricSigner(new Sha256, InMemory::plainText($outsider['private']), InMemory::plainText($outsider['public']));
    $token = $configuration->builder()->permittedFor($client->id)->identifiedBy($stored->id)->relatedTo((string) $stored->user_id)
        ->issuedAt(now()->toDateTimeImmutable())->expiresAt(now()->addHour()->toDateTimeImmutable())->withClaim('scopes', ['openid'])
        ->withHeader('jku', 'https://untrusted.example/keys')->getToken($configuration->signer(), $configuration->signingKey())->toString();
    expect(oauthBearerWorks($token))->toBeFalse()->and(app(ReadToken::class)->access($token))->toBeNull();
    Http::assertNothingSent();
});

it('keeps expired access invalid for resources while allowing its trusted signature for cleanup lookup', function (): void {
    $oldPublic = config('passport.public_key');
    $keys = app(OidcKeys::class);
    $configuration = Configuration::forAsymmetricSigner(new Sha256, $keys->privateKey(), $keys->publicKey());
    $identifier = Str::random(80);
    $token = $configuration->builder()->permittedFor('synthetic-client')->identifiedBy($identifier)->relatedTo('synthetic-user')
        ->issuedAt(now()->subHours(2)->toDateTimeImmutable())->expiresAt(now()->subHour()->toDateTimeImmutable())
        ->withClaim('scopes', [])->getToken($configuration->signer(), $configuration->signingKey())->toString();
    rotationConfigure(rotationPair(1), [$oldPublic]);
    expect(oauthBearerWorks($token))->toBeFalse()->and(app(ReadToken::class)->access($token) === $identifier)->toBeTrue();
});

it('deduplicates public material and publishes only safe RSA parameters', function (): void {
    $active = config('passport.public_key');
    $next = rotationPair(1)['public'];
    config(['oauth_keys.additional_public_keys' => json_encode([$active, $next, str_replace("\n", '\\n', $next)])]);
    $jwks = $this->getJson('/.well-known/jwks.json')->assertOk()->json('keys');
    expect($jwks)->toHaveCount(2);
    foreach ($jwks as $jwk) {
        expect(array_keys($jwk))->toEqualCanonicalizing(['kty', 'use', 'alg', 'kid', 'n', 'e']);
        expect($jwk['alg'])->toBe('RS256');
    }
});

it('rejects malformed weak mismatched private-in-public and excessive key configuration safely', function (string $case): void {
    match ($case) {
        'json' => config(['oauth_keys.additional_public_keys' => 'not-json']),
        'map' => config(['oauth_keys.additional_public_keys' => ['unexpected' => rotationPair(1)['public']]]),
        'invalid' => config(['oauth_keys.additional_public_keys' => ['synthetic-invalid-key']]),
        'path' => config(['oauth_keys.additional_public_keys' => ['file://unapproved-public.key']]),
        'url' => config(['oauth_keys.additional_public_keys' => ['https://untrusted.example/key.pem']]),
        'private' => config(['oauth_keys.additional_public_keys' => [rotationPair(1)['private']]]),
        'mismatch' => config(['passport.public_key' => rotationPair(1)['public']]),
        'limit' => config(['oauth_keys.additional_public_keys' => [rotationPair(1)['public'], rotationPair(2)['public'], rotationPair(3)['public']]]),
        'weak' => config(['oauth_keys.additional_public_keys' => [(string) RSA::createKey(1024)->getPublicKey()]]),
        'ec' => config(['oauth_keys.additional_public_keys' => [(string) EC::createKey('secp256r1')->getPublicKey()]]),
    };
    expect(fn () => app(OidcKeys::class)->publicKeys())->toThrow(RuntimeException::class, 'OAuth signing key configuration is invalid.');
    expect(fn () => app(AuthorizationServer::class))->toThrow(RuntimeException::class, 'OAuth signing key configuration is invalid.');
})->with(['json', 'map', 'invalid', 'path', 'url', 'private', 'mismatch', 'limit', 'weak', 'ec']);

it('preserves old codes and refresh payloads when pinned encryption survives an APP_KEY change', function (): void {
    $oldKey = config('app.key');
    $client = oauthClientFixture();
    $user = User::factory()->create();
    $original = rotationIssue($this, $user, $client);
    $pendingCode = oauthCode($this, $user, $client);
    config(['oauth_keys.payload_encryption_key' => $oldKey]);
    rotationFrameworkKey('base64:'.base64_encode(Encrypter::generateKey(config('app.cipher'))), [$oldKey]);
    $this->postJson('/oauth/token', oauthExchange($client, $pendingCode))->assertOk();
    $this->postJson('/oauth/token', ['grant_type' => 'refresh_token', 'client_id' => $client->id,
        'refresh_token' => $original['refresh_token']])->assertOk();
});

it('demonstrates previous framework keys alone cannot decrypt League refresh payloads', function (): void {
    $oldKey = config('app.key');
    $client = oauthClientFixture();
    $tokens = rotationIssue($this, User::factory()->create(), $client);
    $ciphertext = Crypt::encryptString('synthetic-framework-data');
    rotationFrameworkKey('base64:'.base64_encode(Encrypter::generateKey(config('app.cipher'))), [$oldKey]);
    expect(Crypt::decryptString($ciphertext) === 'synthetic-framework-data')->toBeTrue();
    $this->postJson('/oauth/token', ['grant_type' => 'refresh_token', 'client_id' => $client->id,
        'refresh_token' => $tokens['refresh_token']])->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
});

it('fails closed for an invalid dedicated payload secret', function (mixed $secret): void {
    config(['oauth_keys.payload_encryption_key' => $secret]);
    expect(fn () => app(AuthorizationServer::class))->toThrow(RuntimeException::class, 'OAuth payload encryption configuration is invalid.');
    expect(fn () => app(ReadToken::class))->toThrow(RuntimeException::class, 'OAuth payload encryption configuration is invalid.');
})->with(['', 'too-short', 'base64:not-valid!', 'base64:'.base64_encode('short'), ['invalid']]);

it('recovers Fortify secrets and real encrypted queue commands using previous framework keys', function (): void {
    $user = User::factory()->create();
    app(EnableTwoFactorAuthentication::class)($user);
    $user->forceFill(['two_factor_confirmed_at' => now()])->save();
    $secretHash = hash('sha256', Fortify::currentEncrypter()->decrypt($user->two_factor_secret));
    $recoveryHash = hash('sha256', json_encode($user->recoveryCodes()));
    $exportId = (string) Str::uuid();
    Queue::connection('database')->push(new GenerateAccountExport($exportId));
    $payload = json_decode(DB::table('jobs')->sole()->payload, true, 512, JSON_THROW_ON_ERROR);
    expect(str_starts_with($payload['data']['command'], 'O:'))->toBeFalse();
    $oldKey = config('app.key');
    $newKey = 'base64:'.base64_encode(Encrypter::generateKey(config('app.cipher')));
    rotationFrameworkKey($newKey, [$oldKey]);
    expect(hash('sha256', Fortify::currentEncrypter()->decrypt($user->fresh()->two_factor_secret)) === $secretHash)->toBeTrue();
    expect(hash('sha256', json_encode($user->fresh()->recoveryCodes())) === $recoveryHash)->toBeTrue();
    $decode = new ReflectionMethod(CallQueuedHandler::class, 'getCommand');
    $command = $decode->invoke(app(CallQueuedHandler::class), $payload['data']);
    expect($command instanceof GenerateAccountExport && $command->exportId === $exportId)->toBeTrue();
    $this->post('/login', ['email' => $user->email, 'password' => 'password'])->assertRedirect('/two-factor-challenge');
    $this->post('/two-factor-challenge', ['code' => app(Google2FA::class)->getCurrentOtp(Fortify::currentEncrypter()->decrypt($user->two_factor_secret))])->assertRedirect('/account/profile');
    $this->assertAuthenticatedAs($user);
    rotationFrameworkKey($newKey);
    expect(fn () => $user->fresh()->recoveryCodes())->toThrow(DecryptException::class);
    expect(fn () => $decode->invoke(app(CallQueuedHandler::class), $payload['data']))->toThrow(DecryptException::class);
    expect($user->fresh()->hasEnabledTwoFactorAuthentication())->toBeTrue();
});

it('retains cookie and signed-link verification through Laravel previous-key fallback', function (): void {
    $oldKey = config('app.key');
    $url = URL::temporarySignedRoute('verification.verify', now()->addMinutes(10), ['id' => 1, 'hash' => 'synthetic']);
    $middleware = app(EncryptCookies::class);
    $response = $middleware->handle(Request::create('/'), fn () => response()->noContent()->cookie('rotation-fixture', 'synthetic-value'));
    $cookie = $response->headers->getCookies()[0]->getValue();
    rotationFrameworkKey('base64:'.base64_encode(Encrypter::generateKey(config('app.cipher'))), [$oldKey]);
    expect(URL::hasValidSignature(Request::create($url)))->toBeTrue();
    app(EncryptCookies::class)->handle(Request::create('/', 'GET', [], ['rotation-fixture' => $cookie]), function (Request $request) {
        expect($request->cookie('rotation-fixture') === 'synthetic-value')->toBeTrue();

        return response()->noContent();
    });
});

it('keeps old and new machine tokens introspectable during signing-key overlap', function (): void {
    $machine = app(ClientRepository::class)->createClientCredentialsGrantClient('Rotation fixture');
    $machine->forceFill(['status' => OAuthClientStatus::Live, 'app_type' => OAuthAppType::Machine,
        'allowed_scopes' => ['stats:read']])->save();
    $resource = oauthClientFixture(confidential: true);
    $resource->forceFill(['introspection_client_ids' => [$machine->id]])->save();
    $grant = ['grant_type' => 'client_credentials', 'client_id' => $machine->id, 'client_secret' => $machine->plainSecret, 'scope' => 'stats:read'];
    $old = $this->postJson('/oauth/token', $grant)->assertOk()->json('access_token');
    $oldPublic = config('passport.public_key');
    rotationConfigure(rotationPair(1), [$oldPublic]);
    $new = $this->postJson('/oauth/token', $grant)->assertOk()->json('access_token');
    foreach ([$old, $new] as $token) {
        $this->postJson('/oauth/introspect', ['client_id' => $resource->id, 'client_secret' => $resource->plainSecret, 'token' => $token])
            ->assertOk()->assertJsonPath('active', true)->assertJsonPath('client_id', $machine->id);
    }
    $resource->forceFill(['introspection_client_ids' => []])->save();
    $this->postJson('/oauth/introspect', ['client_id' => $resource->id, 'client_secret' => $resource->plainSecret, 'token' => $old])
        ->assertUnauthorized();
});

it('rejects algorithm substitution even when the token uses an actual stored identifier', function (): void {
    $client = oauthClientFixture();
    rotationIssue($this, User::factory()->create(), $client);
    $stored = Passport::token()->newQuery()->sole();
    $configuration = Configuration::forSymmetricSigner(new Lcobucci\JWT\Signer\Hmac\Sha256, InMemory::plainText(config('passport.public_key')));
    $token = $configuration->builder()->permittedFor($client->id)->identifiedBy($stored->id)->relatedTo((string) $stored->user_id)
        ->issuedAt(now()->toDateTimeImmutable())->expiresAt(now()->addHour()->toDateTimeImmutable())->withClaim('scopes', ['openid'])
        ->getToken($configuration->signer(), $configuration->signingKey())->toString();
    rotationConfigure(rotationPair(1), [config('passport.public_key')]);
    expect(oauthBearerWorks($token))->toBeFalse()->and(app(ReadToken::class)->access($token))->toBeNull();
});

it('accepts the same raw key bytes in canonical framework representations without changing defaults', function (): void {
    $encrypter = app('encrypter');
    $expected = hash('sha256', $encrypter->getKey());
    expect(hash('sha256', Passport::tokenEncryptionKey($encrypter)) === $expected)->toBeTrue();
    config(['oauth_keys.payload_encryption_key' => $encrypter->getKey()]);
    expect(hash('sha256', Passport::tokenEncryptionKey($encrypter)) === $expected)->toBeTrue();
    config(['oauth_keys.payload_encryption_key' => 'base64:'.base64_encode($encrypter->getKey())]);
    expect(hash('sha256', Passport::tokenEncryptionKey($encrypter)) === $expected)->toBeTrue();
});
