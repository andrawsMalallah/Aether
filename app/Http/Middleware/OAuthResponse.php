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

        return $response;
    }
}
