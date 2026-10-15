<?php

namespace App\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;

class WebApplicationUrl implements ValidationRule
{
    public function __construct(private bool $allowLoopbackHttp = false) {}

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (! is_string($value) || ! filter_var($value, FILTER_VALIDATE_URL)
            || preg_match('/\s/', $value) || str_contains(rawurldecode($value), '*')) {
            $fail('Enter a complete URL without spaces or wildcards.');

            return;
        }
        $parts = parse_url($value);
        $host = strtolower($parts['host'] ?? '');
        $scheme = strtolower($parts['scheme'] ?? '');
        $loopback = in_array($host, ['localhost', '127.0.0.1', '[::1]'], true);
        if (isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])
            || ($scheme !== 'https' && ! ($this->allowLoopbackHttp && $scheme === 'http' && $loopback))) {
            $fail($this->allowLoopbackHttp
                ? 'Use HTTPS, or HTTP on localhost/loopback for development. Credentials and fragments are not allowed.'
                : 'Use an HTTPS URL without credentials or a fragment.');
        }
    }
}
