<?php

namespace App\Services;

use Illuminate\Filesystem\FilesystemAdapter;
use Illuminate\Support\Facades\Storage;
use RuntimeException;
use Symfony\Component\HttpFoundation\StreamedResponse;

class PrivateStorage
{
    public static function name(): string
    {
        $name = config('filesystems.private_disk');
        if (! in_array($name, ['local', 'private_s3'], true)) {
            throw new RuntimeException('Private storage configuration is invalid.');
        }
        if ($name === 'private_s3') {
            $settings = config('filesystems.disks.private_s3');
            foreach (['key', 'secret', 'region', 'bucket'] as $required) {
                if (! is_string($settings[$required] ?? null) || trim($settings[$required]) === '') {
                    throw new RuntimeException('Private storage configuration is incomplete.');
                }
            }
            if (($settings['driver'] ?? null) !== 's3' || ($settings['visibility'] ?? null) !== 'private'
                || (isset($settings['endpoint']) && parse_url($settings['endpoint'], PHP_URL_SCHEME) !== 'https')) {
                throw new RuntimeException('Private storage configuration is invalid.');
            }
        }

        return $name;
    }

    public static function disk(): FilesystemAdapter
    {
        return Storage::disk(self::name());
    }

    /** @param array<string, string> $headers */
    public static function response(string $path, string $contentType, array $headers, ?string $downloadName = null): StreamedResponse
    {
        // Open before sending headers: unavailable storage must not produce a successful empty download.
        $stream = self::disk()->readStream($path);
        if (! is_resource($stream)) {
            throw new RuntimeException('Private file could not be opened.');
        }

        $response = response()->stream(function () use ($stream): void {
            try {
                fpassthru($stream);
            } finally {
                fclose($stream);
            }
        }, 200, array_merge($headers, ['Content-Type' => $contentType]));
        if ($downloadName !== null) {
            $response->headers->set('Content-Disposition', $response->headers->makeDisposition('attachment', $downloadName));
        }

        return $response;
    }
}
