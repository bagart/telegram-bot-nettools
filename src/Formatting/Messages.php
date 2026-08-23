<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Formatting;

/**
 * Loader/renderer for the i18n catalog (Formatting/catalog.php).
 * All user-facing strings must come from here (RFC D9, arch-test target).
 */
final class Messages
{
    /** @var array<string, string>|null */
    private static ?array $catalog = null;

    /** @return array<string, string> */
    public static function all(): array
    {
        return self::catalog();
    }

    /**
     * @param  array<string, string|int>  $params
     */
    public static function format(string $key, array $params = []): string
    {
        $catalog = self::catalog();

        if (! isset($catalog[$key])) {
            return $key;
        }

        $replacements = [];
        foreach ($params as $name => $value) {
            $replacements['{'.$name.'}'] = (string) $value;
        }

        return strtr($catalog[$key], $replacements);
    }

    /** @return array<string, string> */
    private static function catalog(): array
    {
        return self::$catalog ??= require __DIR__.'/catalog.php';
    }
}
