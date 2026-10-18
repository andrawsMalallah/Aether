<?php

namespace App\Services;

class BrowserDescription
{
    public function describe(string $agent): string
    {
        $browser = $this->label($agent, ['Edg/' => 'Edge', 'Firefox/' => 'Firefox', 'Chrome/' => 'Chrome', 'Safari/' => 'Safari'], 'Unknown browser');
        $device = $this->label($agent, ['Android' => 'Android', 'iPhone' => 'iPhone', 'iPad' => 'iPad', 'Windows' => 'Windows', 'Macintosh' => 'macOS', 'Linux' => 'Linux'], 'unknown device');

        return $browser.' on '.$device;
    }

    /** @param array<string, string> $labels */
    private function label(string $agent, array $labels, string $fallback): string
    {
        foreach ($labels as $needle => $label) {
            if (str_contains($agent, $needle)) {
                return $label;
            }
        }

        return $fallback;
    }
}
