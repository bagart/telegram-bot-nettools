<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

/**
 * IDN homograph warning (RFC §7.1): mixed-script labels and common
 * confusables (Cyrillic "а" vs Latin "a") → anti-phish caution line.
 * Unicode-script heuristics only — no external dependencies.
 */
final class HomographCheck
{
    /** @return string|null warning text when the host looks confusable */
    public static function warningFor(string $punycodeHost): ?string
    {
        foreach (explode('.', $punycodeHost) as $label) {
            if (str_starts_with($label, 'xn--')) {
                return 'punycode label ("'.$label.'") — verify the decoded name';
            }

            $scripts = self::scriptsIn($label);
            if ($scripts['latin'] > 0 && ($scripts['cyrillic'] > 0 || $scripts['greek'] > 0)) {
                return 'mixed-script label ("'.$label.'") — possible homoglyph';
            }
        }

        return null;
    }

    /** @return array{latin: int, cyrillic: int, greek: int} */
    private static function scriptsIn(string $label): array
    {
        $counts = ['latin' => 0, 'cyrillic' => 0, 'greek' => 0];

        foreach (mb_str_split($label) as $char) {
            $code = mb_ord($char);
            if ($code === null) {
                continue;
            }

            if (($code >= 0x41 && $code <= 0x5A) || ($code >= 0x61 && $code <= 0x7A)) {
                $counts['latin']++;
            } elseif ($code >= 0x0400 && $code <= 0x04FF) {
                $counts['cyrillic']++;
            } elseif ($code >= 0x0370 && $code <= 0x03FF) {
                $counts['greek']++;
            }
        }

        return $counts;
    }
}
