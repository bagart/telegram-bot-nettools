<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Unit;

use BAGArt\TelegramBotNettools\Contracts\Exceptions\InvalidTargetException;
use BAGArt\TelegramBotNettools\Support\TargetNormalizer;
use PHPUnit\Framework\TestCase;

final class TargetNormalizerTest extends TestCase
{
    private TargetNormalizer $normalizer;

    protected function setUp(): void
    {
        $this->normalizer = new TargetNormalizer();
    }

    public function test_normalizes_plain_domain(): void
    {
        $input = $this->normalizer->normalize('example.com');

        self::assertSame('example.com', $input->host);
        self::assertFalse($input->isIp);
        self::assertNull($input->port);
    }

    public function test_lowercases_and_strips_trailing_dot(): void
    {
        $input = $this->normalizer->normalize('  EXAMPLE.COM. ');

        self::assertSame('example.com', $input->host);
    }

    public function test_extracts_host_from_url(): void
    {
        $input = $this->normalizer->normalize('https://example.com/a/path?q=1');

        self::assertSame('example.com', $input->host);
        self::assertNull($input->port);
    }

    public function test_keeps_web_ports_from_url(): void
    {
        self::assertSame(80, $this->normalizer->normalize('http://example.com:80/')->port);
        self::assertSame(443, $this->normalizer->normalize('https://example.com:443/')->port);
    }

    public function test_rejects_non_web_port(): void
    {
        $this->expectException(InvalidTargetException::class);
        $this->normalizer->normalize('https://example.com:8080/');
    }

    public function test_rejects_non_http_scheme(): void
    {
        $this->expectException(InvalidTargetException::class);
        $this->normalizer->normalize('ftp://example.com/');
    }

    public function test_converts_idn_to_punycode(): void
    {
        $input = $this->normalizer->normalize('сайт.рф');

        self::assertSame('xn--80aswg.xn--p1ai', $input->host);
        self::assertFalse($input->isIp);
    }

    public function test_detects_bracketed_ipv6(): void
    {
        $input = $this->normalizer->normalize('[2001:db8::1]');

        self::assertTrue($input->isIp);
        self::assertSame('2001:db8::1', $input->host);
    }

    public function test_detects_bare_ipv6(): void
    {
        self::assertTrue($this->normalizer->normalize('2606:4700::1111')->isIp);
    }

    public function test_collapses_ipv4_mapped_ipv6_to_v4(): void
    {
        $input = $this->normalizer->normalize('::ffff:10.0.0.5');

        self::assertTrue($input->isIp);
        self::assertSame('10.0.0.5', $input->host);
    }

    public function test_rejects_control_characters(): void
    {
        $this->expectException(InvalidTargetException::class);
        $this->normalizer->normalize("example\x00.com");
    }

    public function test_rejects_empty_input(): void
    {
        $this->expectException(InvalidTargetException::class);
        $this->normalizer->normalize('   ');
    }

    public function test_rejects_overlong_host(): void
    {
        $this->expectException(InvalidTargetException::class);
        $this->normalizer->normalize(str_repeat('a', 254).'.com');
    }

    public function test_rejects_overlong_label(): void
    {
        $this->expectException(InvalidTargetException::class);
        $this->normalizer->normalize(str_repeat('a', 64).'.com');
    }

    public function test_rejects_empty_label(): void
    {
        $this->expectException(InvalidTargetException::class);
        $this->normalizer->normalize('a..b');
    }

    public function test_allows_underscore_service_labels(): void
    {
        self::assertSame('_dmarc.example.com', $this->normalizer->normalize('_dmarc.example.com')->host);
    }

    public function test_numeric_lookalike_ip_is_treated_as_hostname(): void
    {
        // '999.999.999.999' is not a valid IP but is syntactically a valid
        // hostname — it must NOT crash normalization; DNS will NXDOMAIN it.
        $input = $this->normalizer->normalize('999.999.999.999');

        self::assertFalse($input->isIp);
        self::assertSame('999.999.999.999', $input->host);
    }

    public function test_rejects_invalid_ip_literal(): void
    {
        $this->expectException(InvalidTargetException::class);
        $this->normalizer->normalize('[999.1.1.1]');
    }
}
