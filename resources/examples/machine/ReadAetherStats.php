<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Support\Facades\Http;
use RuntimeException;
use Throwable;

class ReadAetherStats extends Command
{
    protected $signature = 'aether:stats';

    protected $description = 'Read an approved Waraq notes total and revoke the temporary token';

    public function handle(): int
    {
        $issuer = config('aether-machine.issuer');
        $resourceUrl = config('aether-machine.resource_url');
        $clientId = config('aether-machine.client_id');
        $clientSecret = config('aether-machine.client_secret');

        foreach ([$issuer, $resourceUrl] as $url) {
            if (! is_string($url) || ! filter_var($url, FILTER_VALIDATE_URL)
                || parse_url($url, PHP_URL_SCHEME) !== 'https'
                || parse_url($url, PHP_URL_USER) !== null || parse_url($url, PHP_URL_PASS) !== null
                || parse_url($url, PHP_URL_QUERY) !== null || parse_url($url, PHP_URL_FRAGMENT) !== null) {
                $this->error('Configure trusted HTTPS issuer and resource URLs without credentials, queries or fragments.');

                return self::FAILURE;
            }
        }
        if (! is_string($clientId) || $clientId === '' || ! is_string($clientSecret) || $clientSecret === '') {
            $this->error('Configure the Machine client credentials privately before running this command.');

            return self::FAILURE;
        }

        try {
            $notes = $this->readNotes($issuer, $resourceUrl, $clientId, $clientSecret);
        } catch (RuntimeException $exception) {
            $this->error($exception->getMessage());

            return self::FAILURE;
        }

        // No resource output until credential cleanup has succeeded.
        $this->info('Notes: '.$notes.'. Temporary token revoked.');

        return self::SUCCESS;
    }

    private function readNotes(string $issuer, string $resourceUrl, string $clientId, string $clientSecret): int
    {
        $token = null;
        $stage = 'Token request';
        try {
            $response = $this->http()->asForm()->post(rtrim($issuer, '/').'/oauth/token', [
                'grant_type' => 'client_credentials',
                'client_id' => $clientId,
                'client_secret' => $clientSecret,
                'scope' => 'stats:read',
            ]);
            $data = $response->json();
            // Retain a received token for cleanup even if the response is otherwise invalid.
            if (is_array($data) && is_string($data['access_token'] ?? null) && $data['access_token'] !== '') {
                $token = $data['access_token'];
            }
            if (! $response->successful() || $token === null || ! is_array($data)
                || ! is_string($data['token_type'] ?? null) || strcasecmp($data['token_type'], 'Bearer') !== 0
                || ($data['scope'] ?? null) !== 'stats:read'
                || ! is_int($data['expires_in'] ?? null) || $data['expires_in'] <= 0
                || array_key_exists('refresh_token', $data) || array_key_exists('id_token', $data)) {
                throw new RuntimeException;
            }

            $stage = 'Approved resource request';
            $response = $this->http()->withToken($token)->get($resourceUrl);
            $data = $response->json();
            if (! $response->successful() || ! is_array($data) || array_keys($data) !== ['notes']
                || ! is_int($data['notes']) || $data['notes'] < 0) {
                throw new RuntimeException;
            }

            return $data['notes'];
        } catch (Throwable) {
            // Transport exceptions and upstream bodies can contain credentials.
            throw new RuntimeException($stage.' failed. Check availability, administrator approval and resource access.');
        } finally {
            if ($token !== null) {
                try {
                    $revoked = $this->http()->asForm()->post(rtrim($issuer, '/').'/oauth/revoke', [
                        'client_id' => $clientId,
                        'client_secret' => $clientSecret,
                        'token' => $token,
                        'token_type_hint' => 'access_token',
                    ])->successful();
                } catch (Throwable) {
                    $revoked = false;
                }
                if (! $revoked) {
                    throw new RuntimeException('Token cleanup could not be confirmed. No report was printed. Ask the operator to revoke credentials or wait for token expiry.');
                }
            }
        }
    }

    private function http(): PendingRequest
    {
        return Http::withOptions(['allow_redirects' => false])
            ->connectTimeout(2)->timeout(5)->acceptJson();
    }
}
