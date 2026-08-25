<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Unit;

use BAGArt\TelegramBotNettools\Mcp\NettoolsProbeTool;
use BAGArt\TelegramBotNettools\NettoolsServices;
use BAGArt\TelegramBotNettools\Tests\Support\FakeDnsTransport;
use BAGArt\TelegramBotNettools\Tests\Support\FakeHttpSource;
use BAGArt\TelegramBotNettools\Tests\Support\FakeLocker;
use BAGArt\TelegramBotNettools\Tests\Support\FakeOutboundCacheFactory;
use BAGArt\TelegramBotNettools\Tests\Support\FakeProbeFetcher;
use Laravel\Mcp\Request;
use Laravel\Mcp\Response;
use PHPUnit\Framework\TestCase;

/**
 * MCP probe tool end-to-end over the test service bundle. Laravel\Mcp\Request
 * is a plain data bag (ctor takes the arguments array only), so handle() runs
 * standalone without the MCP server runtime.
 */
final class NettoolsProbeToolTest extends TestCase
{
    private NettoolsServices $services;

    private NettoolsProbeTool $tool;

    protected function setUp(): void
    {
        $this->services = NettoolsServices::forTests(
            cache: FakeOutboundCacheFactory::create(),
            locker: new FakeLocker(),
            http: new FakeHttpSource(),
            fetcher: new FakeProbeFetcher(),
            dnsTransport: new FakeDnsTransport(),
        );
        $this->tool = new NettoolsProbeTool($this->services);
    }

    public function test_unknown_probe_rejected(): void
    {
        $response = $this->handle('nmap', '8.8.8.8');

        self::assertTrue($response->isError());
        self::assertSame('probe not available via MCP', (string) $response->content());
        self::assertSame(0, $this->services->quota->usedInChat('mcp'));
    }

    public function test_measurement_probe_ping_rejected(): void
    {
        $response = $this->handle('ping', '8.8.8.8');

        self::assertTrue($response->isError());
        self::assertSame('probe not available via MCP', (string) $response->content());
    }

    public function test_blocked_target_returns_error_and_charges_nothing(): void
    {
        $response = $this->handle('ip', '169.254.169.254');

        self::assertTrue($response->isError());
        self::assertStringContainsString('Blocked', (string) $response->content());
        self::assertSame(0, $this->services->quota->usedInChat('mcp'));
    }

    public function test_ip_probe_returns_payload_and_degraded_sources(): void
    {
        $response = $this->handle('ip', '203.0.113.9');

        self::assertFalse($response->isError());

        /** @var array<string, mixed> $decoded */
        $decoded = json_decode((string) $response->content(), true, 512, JSON_THROW_ON_ERROR);

        self::assertSame('ip', $decoded['probe']);
        self::assertSame('203.0.113.9', $decoded['target']);
        self::assertIsArray($decoded['payload']);
        self::assertSame('203.0.113.9', $decoded['payload']['ip']);
        self::assertArrayHasKey('degraded_sources', $decoded);
        self::assertIsArray($decoded['degraded_sources']);
        self::assertArrayHasKey('latency_ms', $decoded);
        self::assertGreaterThanOrEqual(0, $decoded['latency_ms']);

        // Exactly one unit charged for the successful call
        self::assertSame(1, $this->services->quota->usedInChat('mcp'));
    }

    /**
     * The tool charges identity ('mcp', null), so the binding ledger is the
     * per-chat ceiling (150 units by default), not daily_units — exhausting it
     * needs that many weight-1 charges before the next call is denied.
     */
    public function test_quota_denial_after_exhausting_ledger(): void
    {
        for ($i = 0; $i < 150; $i++) {
            $this->services->quota->charge('mcp', null, 1);
        }

        $response = $this->handle('ip', '203.0.113.9');

        self::assertTrue($response->isError());
        self::assertStringContainsString('Daily quota used', (string) $response->content());

        // Denied requests must not inflate the counter past the ceiling
        self::assertSame(150, $this->services->quota->usedInChat('mcp'));
    }

    private function handle(string $probe, string $target): Response
    {
        return $this->tool->handle(new Request(['probe' => $probe, 'target' => $target]));
    }
}
