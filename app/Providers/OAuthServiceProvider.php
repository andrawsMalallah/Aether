<?php

namespace App\Providers;

use App\Http\Controllers\OAuth\AuthorizationController;
use App\Models\OAuthClient;
use App\Services\OAuth;
use DateInterval;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Laravel\Passport\Bridge;
use Laravel\Passport\ClientRepository;
use Laravel\Passport\Passport;
use League\OAuth2\Server\AuthorizationServer;

class OAuthServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        // Expose only the approved protocol routes, never Passport's default CRUD endpoints.
        Passport::ignoreRoutes();
        Passport::$deviceCodeGrantEnabled = false;
        Passport::$passwordGrantEnabled = false;
        Passport::$implicitGrantEnabled = false;
        $this->app->scoped(OAuth\TokenContext::class);
        $this->app->singleton(ClientRepository::class, OAuth\ClientRepository::class);
        $this->app->bind(Bridge\ClientRepository::class, OAuth\BridgeClientRepository::class);
        $this->app->bind(Bridge\ScopeRepository::class, OAuth\ScopeRepository::class);
        $this->app->bind(Bridge\AccessTokenRepository::class, OAuth\AccessTokenRepository::class);
        $this->app->bind(Bridge\AuthCodeRepository::class, OAuth\AuthCodeRepository::class);
        $this->app->bind(Bridge\RefreshTokenRepository::class, OAuth\RefreshTokenRepository::class);
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
        Passport::useClientModel(OAuthClient::class);
        Passport::authorizationView('oauth.consent');
        Passport::tokensCan(config('oauth.scopes'));
        Passport::tokensExpireIn(new DateInterval('PT1H'));
        Passport::refreshTokensExpireIn(new DateInterval('P30D'));
        Passport::setDefaultScope([]);
        RateLimiter::for('oauth-authorize', fn (Request $request): Limit => Limit::perMinute(30)->by('oauth-authorize:'.$request->session()->getId()));
        foreach (['oauth-token', 'oauth-revoke'] as $limiter) {
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
