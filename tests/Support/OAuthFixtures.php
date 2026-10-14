<?php

use App\Enums\OAuthAppType;
use App\Enums\OAuthClientStatus;
use App\Models\OAuthClient;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Laravel\Passport\ClientRepository;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResourceServer;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Tests\TestCase;

function oauthClientFixture(?User $owner = null, bool $confidential = false): OAuthClient
{
    $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('Test application', ['https://client.example/callback'], $confidential, $owner);
    $client->forceFill([
        'status' => OAuthClientStatus::Live,
        'app_type' => $confidential ? OAuthAppType::Web : OAuthAppType::Spa,
        'allowed_scopes' => ['openid', 'profile', 'email'],
    ])->save();

    return $client;
}

function oauthVerifier(): string
{
    static $verifier;

    return $verifier ??= Str::random(64);
}

/** @return array<string, string> */
function oauthParameters(OAuthClient $client, string $scopes = 'openid'): array
{
    return [
        'client_id' => $client->getKey(), 'response_type' => 'code',
        'redirect_uri' => $client->redirect_uris[0], 'state' => Str::random(32),
        'scope' => $scopes, 'code_challenge_method' => 'S256',
        'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', oauthVerifier(), true)), '+/', '-_'), '='),
    ];
}

/** @param array<string, mixed> $parameters */
function oauthAuthorizeUrl(array $parameters): string
{
    return '/oauth/authorize?'.http_build_query($parameters);
}

function oauthCode(TestCase $test, User $user, OAuthClient $client, string $scopes = 'openid'): string
{
    $response = $test->actingAs($user)->get(oauthAuthorizeUrl(oauthParameters($client, $scopes)));
    if ($response->getStatusCode() === 200) {
        $response = $test->post('/oauth/authorize', ['auth_token' => session('authToken')]);
    }
    expect($response->getStatusCode())->toBe(302);
    parse_str(parse_url($response->headers->get('Location'), PHP_URL_QUERY), $parameters);
    expect(isset($parameters['code']))->toBeTrue();

    return $parameters['code'];
}

/** @return array<string, string> */
function oauthExchange(OAuthClient $client, string $code): array
{
    return [
        'grant_type' => 'authorization_code', 'client_id' => $client->getKey(),
        'code' => $code, 'redirect_uri' => $client->redirect_uris[0], 'code_verifier' => oauthVerifier(),
        ...($client->plainSecret ? ['client_secret' => $client->plainSecret] : []),
    ];
}

function oauthBearerWorks(string $token): bool
{
    $request = (new PsrHttpFactory)->createRequest(Request::create('/resource', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer '.$token]));
    try {
        app(ResourceServer::class)->validateAuthenticatedRequest($request);

        return true;
    } catch (OAuthServerException) {
        return false;
    }
}
