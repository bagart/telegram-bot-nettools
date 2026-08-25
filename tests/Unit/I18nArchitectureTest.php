<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Unit;

use PHPUnit\Framework\TestCase;

/**
 * i18n architecture rules (RFC D9 / §3.9, pragmatic MVP cut):
 *
 *  1. Completeness — every `Messages::format('key')` used in src/ exists in
 *     the catalog (no silent empty strings in production).
 *  2. Processor cleanliness — command/exception layers carry no HTML markup
 *     literals; user-facing copy lives in the catalog or the Ui\ cards.
 *
 * Ui\ card literals are an accepted deviation for the MVP (cards are the
 * design system; extraction tracked as post-MVP polish).
 */
final class I18nArchitectureTest extends TestCase
{
    private const string SRC = __DIR__.'/../../src';

    public function test_every_format_key_exists_in_catalog(): void
    {
        $catalog = require self::SRC.'/Formatting/catalog.php';
        self::assertIsArray($catalog);

        $used = [];
        foreach ($this->phpFiles(self::SRC) as $file) {
            $source = file_get_contents($file) ?: '';

            if (preg_match_all("/Messages::format\\(\\s*'([a-z0-9_]+)'/", $source, $m)) {
                foreach ($m[1] as $key) {
                    $used[$key][] = basename($file);
                }
            }
        }

        self::assertNotSame([], $used, 'sanity: Messages::format is actually used');

        foreach ($used as $key => $files) {
            self::assertArrayHasKey(
                $key,
                $catalog,
                "catalog.php misses key '{$key}' used in ".implode(',', $files),
            );
        }
    }

    public function test_command_layer_has_no_html_markup_literals(): void
    {
        $violations = [];

        foreach (['Commands', 'Contracts/Exceptions'] as $dir) {
            foreach ($this->phpFiles(self::SRC.'/'.$dir) as $file) {
                $source = file_get_contents($file) ?: '';
                $tokens = token_get_all($source);

                foreach ($tokens as $token) {
                    if (! is_array($token) || $token[0] !== T_CONSTANT_ENCAPSED_STRING) {
                        continue;
                    }

                    $value = $token[1];
                    // strip heredoc-safe: only double/single string bodies matter
                    if (preg_match('/<\\/?b>|<\\/?i>|<pre>/i', $value) === 1) {
                        $violations[] = basename($file).': '.$value;
                    }
                }
            }
        }

        self::assertSame([], $violations, 'HTML markup must live in the catalog or Ui\\ cards');
    }

    /** @return list<string> */
    private function phpFiles(string $dir): array
    {
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir, \RecursiveDirectoryIterator::SKIP_DOTS));
        $files = [];

        foreach ($iterator as $file) {
            if ($file->isFile() && strtolower($file->getExtension()) === 'php') {
                $files[] = (string) $file->getPathname();
            }
        }

        sort($files);

        return $files;
    }
}
