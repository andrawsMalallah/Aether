<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class OAuthResponse
{
    /** @param Closure(Request): Response $next */
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);
        // Laravel renders route exceptions inside this middleware; preserve throttle headers only.
        if ($response->getStatusCode() >= 400 && $request->is('oauth/authorize') && ! $request->expectsJson()) {
            $headers = array_intersect_key($response->headers->all(), array_flip(['retry-after', 'x-ratelimit-limit', 'x-ratelimit-remaining']));
            $response = response()->view('oauth.error', [], $response->getStatusCode(), $headers);
        }
        $response->headers->set('Cache-Control', 'no-store, private');
        $response->headers->set('Pragma', 'no-cache');
        $response->headers->set('Referrer-Policy', 'no-referrer');
        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('Content-Security-Policy', "frame-ancestors 'none'");

        return $response;
    }
}
