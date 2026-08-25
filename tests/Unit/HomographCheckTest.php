<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Unit;

use BAGArt\TelegramBotNettools\Support\HomographCheck;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Confusables dataset (RFC §7.1 smart hints, Phase 2.9): mixed-script and
 * punycode labels warn; pure single-script hosts never do (false-positive
 * review list from the plan).
 */
final class HomographCheckTest extends TestCase
{
    /** @return list<array{0: string, 1: string}> host, expected warning fragment */
    public static function confusableProvider(): array
    {
        return [
            // Cyrillic а/о/е inside a Latin label — classic paypal/аpple scams
            ['xn--80ak6aa92e', 'punycode label'],
            ['pаypal.com', 'mixed-script label'],       // first а is U+0430
            ['аpple.com', 'mixed-script label'],
            ['gооgle.com', 'mixed-script label'],        // о is U+043E
            // Greek omicron ο (U+03BF) in a Latin label
            ['micrοsoft.com', 'mixed-script label'],
            // punycode TLD label
            ['пример.xn--p1ai', 'punycode label'],
        ];
    }

    /** @return list<list<string>> */
    public static function cleanProvider(): array
    {
        return [
            ['example.org'],
            ['www.google.com'],
            ['mail.example.co.uk'],
            ['muenchen-de.example'],        // single non-Latin script, no mixing
            ['россия.рф'],
            ['123.45.67.89'],
            ['a-b_c.example'],
        ];
    }

    #[DataProvider('confusableProvider')]
    public function test_confusables_warn(string $host, string $fragment): void
    {
        $warning = HomographCheck::warningFor($host);

        self::assertNotNull($warning, "{$host} must warn");
        self::assertStringContainsString($fragment, $warning);
    }

    #[DataProvider('cleanProvider')]
    public function test_clean_hosts_stay_silent(string $host): void
    {
        if (str_starts_with($host, 'xn--')) {
            self::markTestSkipped('covered by confusableProvider');
        }

        self::assertNull(HomographCheck::warningFor($host), "{$host} must NOT warn");
    }

    public function test_punycode_label_is_quoted_verbatim(): void
    {
        $warning = HomographCheck::warningFor('xn--80ak6aa92e.com');

        self::assertSame('punycode label ("xn--80ak6aa92e") — verify the decoded name', $warning);
    }
}
