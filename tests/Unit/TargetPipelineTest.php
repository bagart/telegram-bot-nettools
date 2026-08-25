<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Unit;

use BAGArt\TelegramBotNettools\Contracts\Exceptions\InvalidTargetException;
use BAGArt\TelegramBotNettools\Contracts\Exceptions\TargetBlockedException;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Support\TargetPipeline;
use PHPUnit\Framework\TestCase;

/**
 * IP-literal paths only — no network in unit tests. Domain resolution is
 * exercised by Phase 1 DnsClient fixtures.
 */
final class TargetPipelineTest extends TestCase
{
    private TargetPipeline $pipeline;

    protected function setUp(): void
    {
        $this->pipeline = new TargetPipeline();
    }

    public function test_builds_target_from_ip_literal(): void
    {
        $target = $this->pipeline->inspect('8.8.8.8');

        self::assertSame('8.8.8.8', $target->host);
        self::assertSame(['8.8.8.8'], $target->ips);
        self::assertTrue($target->isIp);
        self::assertFalse($target->isDomain);
        self::assertTrue($target->verdict->allowed);
        self::assertNull($target->verdict->label);
    }

    public function test_documentation_ip_gets_label(): void
    {
        $target = $this->pipeline->inspect('203.0.113.9');

        self::assertTrue($target->verdict->allowed);
        self::assertSame('TEST-NET-3', $target->verdict->label);
    }

    public function test_private_ip_throws_blocked(): void
    {
        try {
            $this->pipeline->inspect('10.1.2.3');
            self::fail('expected TargetBlockedException');
        } catch (TargetBlockedException $exception) {
            self::assertStringContainsString('RFC1918', $exception->userMessage());
        }
    }

    public function test_metadata_endpoint_blocked(): void
    {
        $this->expectException(TargetBlockedException::class);
        $this->pipeline->inspect('169.254.169.254');
    }

    public function test_invalid_input_throws(): void
    {
        $this->expectException(InvalidTargetException::class);
        $this->pipeline->inspect('not a host at all!!');
    }

    public function test_options_cache_hash_is_order_insensitive(): void
    {
        $a = new ProbeOptions(['brute' => true, 'limit' => 5], 7);
        $b = new ProbeOptions(['limit' => 5, 'brute' => true], 7);

        self::assertSame($a->cacheHash(), $b->cacheHash());
        self::assertNotSame($a->cacheHash(), (new ProbeOptions())->cacheHash());
    }
}
