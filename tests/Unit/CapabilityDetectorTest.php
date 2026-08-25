<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Unit;

use BAGArt\TelegramBotNettools\Support\CapabilityDetector;
use BAGArt\TelegramBotNettools\Tests\Support\FakeOutboundCacheFactory;
use PHPUnit\Framework\TestCase;

final class CapabilityDetectorTest extends TestCase
{
    public function test_detects_binary_via_seam(): void
    {
        $detector = new CapabilityDetector(
            FakeOutboundCacheFactory::create(),
            binaryExists: fn (string $binary): bool => $binary === 'ping',
        );

        self::assertTrue($detector->pingAvailable());
        self::assertNull($detector->traceBinary());
    }

    public function test_trace_prefers_traceroute_then_tracepath(): void
    {
        $both = new CapabilityDetector(
            FakeOutboundCacheFactory::create(),
            binaryExists: fn (string $b): bool => in_array($b, ['traceroute', 'tracepath'], true),
        );
        self::assertSame('traceroute', $both->traceBinary());

        $onlyPath = new CapabilityDetector(
            FakeOutboundCacheFactory::create(),
            binaryExists: fn (string $b): bool => $b === 'tracepath',
        );
        self::assertSame('tracepath', $onlyPath->traceBinary());
    }

    public function test_result_is_cached_forever(): void
    {
        $calls = 0;
        $cache = FakeOutboundCacheFactory::create();
        $detector = new CapabilityDetector($cache, binaryExists: function () use (&$calls): bool {
            $calls++;

            return true;
        });

        self::assertTrue($detector->hasBinary('ping'));
        self::assertTrue($detector->hasBinary('ping'));

        self::assertSame(1, $calls);

        // warm() covers all known binaries without extra probes for ping
        $detector->warm();
        self::assertLessThanOrEqual(3, $calls);
    }

    public function test_summary_lines_render_marks(): void
    {
        $detector = new CapabilityDetector(
            FakeOutboundCacheFactory::create(),
            binaryExists: fn (string $b): bool => $b === 'traceroute',
        );

        $lines = $detector->summaryLines();

        self::assertSame('ping: ⚠️ missing', $lines[0]);
        self::assertSame('trace: traceroute ✅', $lines[1]);
    }
}
