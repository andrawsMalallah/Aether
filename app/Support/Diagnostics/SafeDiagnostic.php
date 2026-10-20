<?php

namespace App\Support\Diagnostics;

use Throwable;

final class SafeDiagnostic
{
    /** @return array{exception_class: string, file: string, line: int, frames: list<array{file: string, line: int}>} */
    public static function describe(Throwable $exception): array
    {
        $frames = [];
        foreach (array_slice($exception->getTrace(), 0, 20) as $frame) {
            if (isset($frame['file'], $frame['line'])) {
                $frames[] = ['file' => $frame['file'], 'line' => $frame['line']];
            }
        }

        return [
            'exception_class' => $exception::class,
            'file' => $exception->getFile(),
            'line' => $exception->getLine(),
            'frames' => $frames,
        ];
    }

    public static function text(Throwable $exception): string
    {
        return json_encode(self::describe($exception), JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }
}
