<?php

use App\Exceptions\Handler;
use App\Http\Middleware\RestrictDeletingAccount;
use App\Http\Middleware\SecurityHeaders;
use App\Http\Middleware\SerializeAccountIdentityChanges;
use App\Support\Diagnostics\SafeLogManager;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use League\OAuth2\Server\Exception\OAuthServerException;

$application = Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__.'/../routes/web.php',
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
        then: fn () => Route::group([], base_path('routes/oauth.php')),
    )
    ->withMiddleware(function (Middleware $middleware): void {
        // Wrap early responses as well as routed pages, including CORS preflights.
        $middleware->prepend(SecurityHeaders::class);
        $middleware->appendToGroup('web', [
            SerializeAccountIdentityChanges::class,
            RestrictDeletingAccount::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        // One-time credentials must never be retained as old form input.
        $exceptions->dontFlash(['code', 'recovery_code', 'client_secret', 'code_verifier', 'refresh_token', 'access_token', 'id_token', 'token', 'auth_token']);
        $exceptions->dontReport([OAuthServerException::class]);
        $exceptions->shouldRenderJsonWhen(
            fn (Request $request) => $request->is('api/*') || $request->expectsJson(),
        );
    })->create();

// Install before kernel bootstrapping so provider/configuration failures use safe diagnostics too.
$application->singleton('log', fn (Application $application): SafeLogManager => new SafeLogManager($application));
$application->singleton(ExceptionHandler::class, Handler::class);

return $application;
