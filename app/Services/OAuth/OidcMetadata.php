<?php

namespace App\Services\OAuth;

use RuntimeException;

class OidcMetadata
{
    public function issuer(): string
    {
        $issuer = rtrim((string) config('oidc.issuer'), '/');
        $scheme = parse_url($issuer, PHP_URL_SCHEME);
        if (! parse_url($issuer, PHP_URL_HOST) || parse_url($issuer, PHP_URL_QUERY) !== null || parse_url($issuer, PHP_URL_FRAGMENT) !== null
            || parse_url($issuer, PHP_URL_USER) !== null || ($scheme !== 'https' && ! (app()->environment(['local', 'testing']) && $scheme === 'http'))) {
            throw new RuntimeException('Configure a canonical HTTPS OIDC issuer; HTTP is local/testing only.');
        }

        return $issuer;
    }

    /** @return array<string, mixed> */
    public function discovery(): array
    {
        $issuer = $this->issuer();

        return [
            'issuer' => $issuer,
            'authorization_endpoint' => $issuer.'/oauth/authorize',
            'token_endpoint' => $issuer.'/oauth/token',
            'userinfo_endpoint' => $issuer.'/oauth/userinfo',
            'jwks_uri' => $issuer.'/.well-known/jwks.json',
            'revocation_endpoint' => $issuer.'/oauth/revoke',
            'introspection_endpoint' => $issuer.'/oauth/introspect',
            'scopes_supported' => array_keys(config('oauth.scopes')),
            'response_types_supported' => ['code'],
            'response_modes_supported' => ['query'],
            'grant_types_supported' => ['authorization_code', 'refresh_token', 'client_credentials'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256'],
            'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'none'],
            'revocation_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'none'],
            'introspection_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post'],
            'code_challenge_methods_supported' => ['S256'],
            'claims_supported' => ['iss', 'aud', 'sub', 'exp', 'iat', 'auth_time', 'nonce', 'name', 'email', 'email_verified'],
            'claims_parameter_supported' => false,
            'request_parameter_supported' => false,
            'request_uri_parameter_supported' => false,
        ];
    }
}
