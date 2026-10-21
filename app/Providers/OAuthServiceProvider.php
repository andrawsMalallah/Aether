<?php

namespace App\Providers;

use App\Http\Controllers\OAuth\AuthorizationController;
use App\Models\OAuthClient;
use App\Services\OAuth;
use DateInterval;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Logout;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Laravel\Passport\Bridge;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\ResourceServer;

class OAuthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        // Expose only the approved protocol routes, never Passport's default CRUD endpoints.
        Passport::ignoreRoutes();
        Passport::$deviceCodeGrantEnabled = false;
        Passport::$passwordGrantEnabled = false;
        Passport::$implicitGrantEnabled = false;
        Passport::useAuthorizationServerResponseType(new OAuth\OidcTokenResponse);
        $this->app->scoped(OAuth\TokenContext::class);
        $this->app->singleton(ClientRepository::class, OAuth\ClientRepository::class);
        $this->app->bind(Bridge\ClientRepository::class, OAuth\BridgeClientRepository::class);
        $this->app->bind(Bridge\ScopeRepository::class, OAuth\ScopeRepository::class);
        $this->app->bind(Bridge\AccessTokenRepository::class, OAuth\AccessTokenRepository::class);
        $this->app->bind(Bridge\AuthCodeRepository::class, OAuth\AuthCodeRepository::class);
        $this->app->bind(Bridge\RefreshTokenRepository::class, OAuth\RefreshTokenRepository::class);
        Passport::encryptTokensUsing(fn (Encrypter $encrypter): string => app(OAuth\PayloadEncryptionKey::class)->resolve($encrypter));
        $this->app->beforeResolving(AuthorizationServer::class, function (): void {
            // Validate the complete active pair/ring before Passport can issue even a
            // non-OIDC token; a bad public/private pairing must fail closed.
            app(OAuth\OidcKeys::class)->publicKeys();
        });
        $this->app->singleton(ResourceServer::class, function (): ResourceServer {
            $keys = app(OAuth\OidcKeys::class);
            $repository = app(Bridge\AccessTokenRepository::class);

            return new ResourceServer($repository, new CryptKey($keys->publicKey()->contents(), null, false),
                new OAuth\TrustedBearerTokenValidator($repository, $keys));
        });
        $this->app->when(AuthorizationController::class)->needs(StatefulGuard::class)->give(fn () => Auth::guard('web'));
        $this->app->extend(AuthorizationServer::class, function (AuthorizationServer $server): AuthorizationServer {
            $grant = new OAuth\AuthorizationCodeGrant(app(Bridge\AuthCodeRepository::class), app(Bridge\RefreshTokenRepository::class), new DateInterval('PT1M'));
            $grant->setRefreshTokenTTL(new DateInterval('P30D'));
            $server->enableGrantType($grant, new DateInterval('PT1H'));
            $server->revokeRefreshTokens(true);

            return $server;
        });
    }

    public function boot(): void
    {
        Event::listen(Login::class, function (Login $event): void {
            if ($event->guard === 'web' && request()->hasSession()) {
                request()->session()->put('oidc', ['auth_time' => now()->timestamp, 'user_id' => (string) $event->user->getAuthIdentifier()]);
            }
        });
        Event::listen(Logout::class, function (Logout $event): void {
            if ($event->guard === 'web' && request()->hasSession()) {
                request()->session()->forget('oidc');
            }
        });
        RateLimiter::for('oidc-userinfo', fn (Request $request): array => [
            // A fingerprint identifies the rate bucket without retaining the bearer credential.
            Limit::perMinute(120)->by('oidc-userinfo:token:'.hash('sha256', $request->bearerToken() ?? 'guest:'.$request->ip())),
            Limit::perMinute(240)->by('oidc-userinfo:ip:'.$request->ip()),
        ]);
        Passport::useClientModel(OAuthClient::class);
        Passport::authorizationView('oauth.consent');
        Passport::tokensCan(config('oauth.scopes'));
        Passport::tokensExpireIn(new DateInterval('PT1H'));
        Passport::refreshTokensExpireIn(new DateInterval('P30D'));
        Passport::setDefaultScope([]);
        RateLimiter::for('oauth-authorize', fn (Request $request): Limit => Limit::perMinute(30)->by('oauth-authorize:'.$request->session()->getId()));
        foreach (['oauth-token', 'oauth-revoke', 'oauth-introspect'] as $limiter) {
            RateLimiter::for($limiter, function (Request $request) use ($limiter): array {
                $clientId = $request->input('client_id', $request->getUser());

                return [
                    Limit::perMinute(60)->by($limiter.':client:'.(is_string($clientId) ? $clientId : 'invalid')),
                    Limit::perMinute(120)->by($limiter.':ip:'.$request->ip()),
                ];
            });
        }
    }
}
