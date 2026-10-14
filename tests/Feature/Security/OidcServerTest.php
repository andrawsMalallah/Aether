<?php

use App\Enums\OAuthAppType;
use App\Enums\OAuthClientStatus;
use App\Models\OAuthClient;
use App\Models\User;
use App\Services\OAuth\OidcKeys;
use App\Services\OAuth\OidcMetadata;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use phpseclib4\Crypt\RSA;
use Tests\TestCase;

uses(RefreshDatabase::class);

beforeEach(function (): void {
    static $keys;
    $keys ??= RSA::createKey(2048);
    config(['passport.private_key' => (string) $keys, 'passport.public_key' => (string) $keys->getPublicKey(), 'oidc.issuer' => 'https://aether.example']);
});

function oidcParse(string $encoded): UnencryptedToken
{
    $keys = app(OidcKeys::class);
    $configuration = Configuration::forAsymmetricSigner(new Sha256, $keys->privateKey(), $keys->publicKey());
    $token = $configuration->parser()->parse($encoded);
    expect($token)->toBeInstanceOf(UnencryptedToken::class);
    expect($configuration->validator()->validate($token, new SignedWith($configuration->signer(), $keys->publicKey())))->toBeTrue();

    return $token;
}

/** @return array<string, mixed> */
function oidcAuthorize(TestCase $test, User $user, OAuthClient $client, string $scope = 'openid profile email', ?string $nonce = 'original-nonce'): array
{
    $parameters = oauthParameters($client, $scope);
    if ($nonce !== null) {
        $parameters['nonce'] = $nonce;
    }
    $response = $test->actingAs($user)->get(oauthAuthorizeUrl($parameters));
    if ($response->getStatusCode() === 200) {
        // An approval submission cannot replace the nonce captured at authorization.
        $response = $test->post('/oauth/authorize', ['auth_token' => session('authToken'), 'nonce' => 'attacker-nonce']);
    }
    $response->assertRedirect();
    parse_str(parse_url($response->headers->get('Location'), PHP_URL_QUERY), $callback);

    return $test->postJson('/oauth/token', [...oauthExchange($client, $callback['code']), 'nonce' => 'exchange-nonce'])->assertOk()->json();
}

it('issues signed audience-bound identity with original nonce authentication time and scope claims', function (): void {
    $user = User::factory()->create();
    $tokens = oidcAuthorize($this, $user, oauthClientFixture());
    $token = oidcParse($tokens['id_token']);
    $code = Passport::authCode()->newQuery()->first();
    expect($token->claims()->get('iss'))->toBe('https://aether.example');
    expect($token->claims()->get('aud'))->toBe([$code->client_id]);
    expect($token->claims()->get('sub'))->toBe((string) $user->getKey());
    expect($token->claims()->get('nonce'))->toBe('original-nonce');
    expect($token->claims()->get('auth_time'))->toBe((int) $code->oidc_auth_time);
    expect($token->claims()->get('exp')->getTimestamp() - $token->claims()->get('iat')->getTimestamp())->toBe(3600);
    expect($token->claims()->get('name'))->toBe($user->name);
    expect($token->claims()->get('email'))->toBe($user->email);
    expect($token->claims()->get('email_verified'))->toBeTrue();
    expect($token->claims()->has('password'))->toBeFalse();
    expect($token->claims()->has('picture'))->toBeFalse();
    $jwks = $this->getJson('/.well-known/jwks.json')->assertOk()->json('keys.0');
    expect($token->headers()->get('kid'))->toBe($jwks['kid']);
    // Independently reconstruct the verification key from published JOSE parameters.
    $publicKey = RSA::loadPublicKeyFormat('JWK', json_encode(['keys' => [$jwks]], JSON_THROW_ON_ERROR));
    $segments = explode('.', $tokens['id_token']);
    $signature = base64_decode(strtr($segments[2], '-_', '+/'));
    expect($publicKey->withPadding(RSA::SIGNATURE_PKCS1)->withHash('sha256')->verify($segments[0].'.'.$segments[1], $signature))->toBeTrue();
    expect(array_intersect(['d', 'p', 'q', 'dp', 'dq', 'qi'], array_keys($jwks)))->toBe([]);
});

it('filters both identity token and userinfo claims by granted scope', function (string $scope, bool $profile, bool $email): void {
    $user = User::factory()->create();
    $tokens = oidcAuthorize($this, $user, oauthClientFixture(), $scope, null);
    $token = oidcParse($tokens['id_token']);
    expect($token->claims()->has('nonce'))->toBeFalse();
    expect($token->claims()->has('name'))->toBe($profile);
    expect($token->claims()->has('email'))->toBe($email);
    expect($token->claims()->has('email_verified'))->toBe($email);
    $claims = $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$tokens['access_token']])->assertOk()->assertHeader('Cache-Control', 'no-store, private')->json();
    expect($claims['sub'])->toBe((string) $user->getKey());
    expect(array_key_exists('name', $claims))->toBe($profile);
    expect(array_key_exists('email', $claims))->toBe($email);
    expect(array_key_exists('email_verified', $claims))->toBe($email);
    $this->postJson('/oauth/userinfo', [], ['Authorization' => 'Bearer '.$tokens['access_token']])->assertOk()->assertExactJson($claims);
})->with([['openid', false, false], ['openid profile', true, false], ['openid email', false, true]]);

it('does not issue identity for non-openid or machine grants', function (): void {
    $client = oauthClientFixture();
    expect(oidcAuthorize($this, User::factory()->create(), $client, 'profile'))->not->toHaveKey('id_token');
    $machine = app(ClientRepository::class)->createClientCredentialsGrantClient('Machine');
    $machine->forceFill(['status' => OAuthClientStatus::Live, 'app_type' => OAuthAppType::Machine, 'allowed_scopes' => ['openid']])->save();
    $tokens = $this->postJson('/oauth/token', ['grant_type' => 'client_credentials', 'client_id' => $machine->getKey(), 'client_secret' => $machine->plainSecret, 'scope' => 'openid'])->assertOk()->json();
    expect($tokens)->not->toHaveKey('id_token');
    $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$tokens['access_token']])->assertUnauthorized();
});

it('preserves original authentication context through refresh scope reduction', function (): void {
    $client = oauthClientFixture();
    $tokens = oidcAuthorize($this, User::factory()->create(), $client);
    $original = oidcParse($tokens['id_token']);
    $this->travel(10)->minutes();
    $refreshed = $this->postJson('/oauth/token', ['grant_type' => 'refresh_token', 'client_id' => $client->getKey(), 'refresh_token' => $tokens['refresh_token'], 'scope' => 'openid', 'nonce' => 'replacement'])->assertOk()->json();
    $identity = oidcParse($refreshed['id_token']);
    expect($identity->claims()->get('auth_time'))->toBe($original->claims()->get('auth_time'));
    expect($identity->claims()->get('nonce'))->toBe('original-nonce');
    expect($identity->claims()->has('email'))->toBeFalse();
    expect($identity->claims()->get('iat')->getTimestamp())->toBeGreaterThan($original->claims()->get('iat')->getTimestamp());
});

it('requires a valid user bearer token with openid regardless of browser login', function (): void {
    $this->actingAs(User::factory()->create())->getJson('/oauth/userinfo')->assertUnauthorized()->assertHeader('WWW-Authenticate', 'Bearer error="invalid_token"');
    $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer invalid'])->assertUnauthorized();
    $client = oauthClientFixture();
    $tokens = oidcAuthorize($this, User::factory()->create(), $client, 'profile');
    $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$tokens['access_token']])->assertForbidden();
    $tokens = oidcAuthorize($this, User::factory()->create(), $client);
    Passport::token()->newQuery()->update(['revoked' => true]);
    $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$tokens['access_token']])->assertUnauthorized();
});

it('publishes accurate discovery and stable public keys independent of request host', function (): void {
    $metadata = $this->getJson('/.well-known/openid-configuration', ['Host' => 'attacker.example'])->assertOk()->json();
    expect($metadata['issuer'])->toBe('https://aether.example');
    expect($metadata['jwks_uri'])->toBe('https://aether.example/.well-known/jwks.json');
    expect($metadata['response_types_supported'])->toBe(['code']);
    expect($metadata['code_challenge_methods_supported'])->toBe(['S256']);
    expect($metadata['claims_supported'])->not->toContain('picture');
    expect($this->getJson('/.well-known/jwks.json')->assertOk()->json())->toBe($this->getJson('/.well-known/jwks.json')->assertOk()->json());
});

it('records real login time and forces legacy sessions to authenticate without falsifying auth_time', function (): void {
    $user = User::factory()->create();
    $client = oauthClientFixture();
    $this->post('/login', ['email' => $user->email, 'password' => 'password'])->assertRedirect();
    expect(session('oidc.user_id'))->toBe((string) $user->getKey());
    $time = session('oidc.auth_time');
    $this->travel(2)->minutes();
    $this->get(oauthAuthorizeUrl(oauthParameters($client)))->assertOk();
    $this->post('/oauth/authorize', ['auth_token' => session('authToken')])->assertRedirect();
    expect((int) Passport::authCode()->newQuery()->first()->oidc_auth_time)->toBe($time);
    $this->withSession(['oidc' => []])->get(oauthAuthorizeUrl([...oauthParameters($client), 'prompt' => 'none']))->assertRedirectContains('error=login_required');
    $this->get(oauthAuthorizeUrl(oauthParameters($client)))->assertRedirect('/login');
});

it('rejects malformed nonce and unsupported OIDC parameters', function (array $extra): void {
    $this->get(oauthAuthorizeUrl([...oauthParameters(oauthClientFixture()), ...$extra]))->assertStatus(400)->assertHeaderMissing('Location');
})->with([[['nonce' => ['nested']]], [['nonce' => str_repeat('x', 1025)]], [['max_age' => 0]], [['response_mode' => 'form_post']], [['claims' => '{}']], [['request_uri' => 'https://attacker.example']]]);

it('blocks HTTP issuers outside local and testing', function (): void {
    config(['oidc.issuer' => 'http://aether.example']);
    app()->instance('env', 'production');
    expect(fn () => app(OidcMetadata::class)->issuer())->toThrow(RuntimeException::class);
});

it('refreshes identity after expired codes are purged without losing context', function (): void {
    $client = oauthClientFixture();
    $tokens = oidcAuthorize($this, User::factory()->create(), $client);
    $original = oidcParse($tokens['id_token']);
    $this->travel(2)->minutes();
    // Simulate expired-code cleanup in this isolated database without purging active tokens.
    Passport::authCode()->newQuery()->where('expires_at', '<', now())->delete();
    expect(Passport::authCode()->newQuery()->count())->toBe(0);
    $refreshed = $this->postJson('/oauth/token', ['grant_type' => 'refresh_token', 'client_id' => $client->getKey(), 'refresh_token' => $tokens['refresh_token']])->assertOk()->json();
    expect(oidcParse($refreshed['id_token'])->claims()->get('auth_time'))->toBe($original->claims()->get('auth_time'));
    expect(oidcParse($refreshed['id_token'])->claims()->get('nonce'))->toBe('original-nonce');
});

it('round trips nonce during first-party and returning-user automatic consent approval', function (bool $firstParty): void {
    $client = oauthClientFixture();
    $client->forceFill(['first_party' => $firstParty])->save();
    $user = User::factory()->create();
    oidcAuthorize($this, $user, $client);
    $parameters = [...oauthParameters($client), 'nonce' => 'automatic-nonce'];
    $response = $this->get(oauthAuthorizeUrl($parameters))->assertRedirect();
    parse_str(parse_url($response->headers->get('Location'), PHP_URL_QUERY), $callback);
    $tokens = $this->postJson('/oauth/token', oauthExchange($client, $callback['code']))->assertOk()->json();
    expect(oidcParse($tokens['id_token'])->claims()->get('nonce'))->toBe('automatic-nonce');
})->with([false, true]);

it('rejects userinfo after token expiry or client suspension', function (bool $suspend): void {
    $client = oauthClientFixture();
    $tokens = oidcAuthorize($this, User::factory()->create(), $client);
    if ($suspend) {
        $client->forceFill(['status' => OAuthClientStatus::Suspended])->save();
    } else {
        // League uses a real clock; Carbon time travel does not expire a signed JWT.
        $keys = app(OidcKeys::class);
        $configuration = Configuration::forAsymmetricSigner(new Sha256, $keys->privateKey(), $keys->publicKey());
        $original = $configuration->parser()->parse($tokens['access_token']);
        $tokens['access_token'] = $configuration->builder()
            ->identifiedBy($original->claims()->get('jti'))->relatedTo($original->claims()->get('sub'))
            ->permittedFor(...$original->claims()->get('aud'))
            ->issuedAt(now()->subHours(2)->toDateTimeImmutable())->expiresAt(now()->subHour()->toDateTimeImmutable())
            ->withClaim('scopes', $original->claims()->get('scopes'))
            ->getToken($configuration->signer(), $configuration->signingKey())->toString();
    }
    $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer '.$tokens['access_token']])->assertUnauthorized();
})->with([false, true]);

it('only grants CORS to explicitly configured origins on approved endpoints', function (): void {
    config(['cors.allowed_origins' => ['https://client.example', 'https://second-client.example']]);
    $this->getJson('/.well-known/openid-configuration', ['Origin' => 'https://client.example'])->assertHeader('Access-Control-Allow-Origin', 'https://client.example')->assertHeaderMissing('Access-Control-Allow-Credentials');
    $this->getJson('/.well-known/jwks.json', ['Origin' => 'https://attacker.example'])->assertHeaderMissing('Access-Control-Allow-Origin');
    $this->get('/login', ['Origin' => 'https://client.example'])->assertHeaderMissing('Access-Control-Allow-Origin');
});

it('rate limits userinfo per bearer fingerprint without retaining credentials', function (): void {
    for ($attempt = 0; $attempt < 120; $attempt++) {
        $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer invalid-fixture'])->assertUnauthorized();
    }
    $this->postJson('/oauth/userinfo', [], ['Authorization' => 'Bearer invalid-fixture'])->assertStatus(429);
    $this->getJson('/oauth/userinfo', ['Authorization' => 'Bearer different-fixture'])->assertUnauthorized();
});
