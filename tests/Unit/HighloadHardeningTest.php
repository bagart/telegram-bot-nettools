<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Unit;

use BAGArt\TelegramBotNettools\Probes\DnsblProbe;
use BAGArt\TelegramBotNettools\Probes\PortScanProbe;
use BAGArt\TelegramBotNettools\Results\GuardVerdict;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Sources\DnsClient;
use BAGArt\TelegramBotNettools\Support\CapabilityDetector;
use BAGArt\TelegramBotNettools\Tests\Support\FakeDnsTransport;
use BAGArt\TelegramBotNettools\Tests\Support\FakeOutboundCacheFactory;
use PHPUnit\Framework\TestCase;

/**
 * Highload hardening gates (todo P2-2/P2-3): wall budgets honored with fake
 * transports, capability cache keys host-scoped, DNSBL timeouts degrade
 * visibly instead of being skipped silently.
 */
final class HighloadHardeningTest extends TestCase
{
    public function test_portscan_stops_at_wall_budget_per_port(): void
    {
        $connect = static function (string $host, int $port): array {
            unset($host, $port);
            usleep(50_000); // 50 ms per connect

            return ['state' => 'closed', 'ms' => 50.0, 'banner' => null];
        };

        $probe = new PortScanProbe(maxPorts: 100, connector: $connect, wallCapSeconds: 1.5);
        $result = $probe->probe(self::target(), new ProbeOptions());

        self::assertLessThan(100, $result->payload['scanned'], 'budget must stop the sweep early');
        self::assertTrue($result->payload['truncated']);
    }

    public function test_capability_cache_key_is_host_scoped(): void
    {
        self::assertNotSame('tg-nettools:cap:ping', CapabilityDetector::cacheKeyFor('ping'), 'bare-name keys poison across hosts');

        $fingerprint = substr(sha1((gethostname() ?: 'unknown').'|'.php_uname('m')), 0, 8);
        self::assertSame('tg-nettools:cap:'.$fingerprint.':ping', CapabilityDetector::cacheKeyFor('ping'));
    }

    public function test_capability_result_is_shared_per_host_and_cached(): void
    {
        $cache = FakeOutboundCacheFactory::create();
        $probes = 0;
        $detector = new CapabilityDetector($cache, static function (string $binary) use (&$probes): bool {
            unset($binary);
            $probes++;

            return true;
        });

        self::assertTrue($detector->hasBinary('ping'));
        self::assertSame(1, $probes);

        // a second detector instance (other worker on the same host) hits the shared key
        $second = new CapabilityDetector($cache, static fn (): bool => throw new \LogicException('must not re-probe'));
        self::assertTrue($second->hasBinary('ping'));
        self::assertSame(true, $cache->get(CapabilityDetector::cacheKeyFor('ping')));
    }

    public function test_dnsbl_timeouted_zones_degrade_visibly(): void
    {
        $transport = new FakeDnsTransport();
        foreach (DnsblProbe::ZONES as $_) {
            $transport->script(['udp' => null]); // every zone unanswered
        }

        $probe = new DnsblProbe(new DnsClient($transport), ['192.0.2.53']);
        $result = $probe->probe(self::target(), new ProbeOptions());

        self::assertSame(0, $result->payload['checked']);
        self::assertCount(count(DnsblProbe::ZONES), $result->degradedSources, 'timeouts are visible, never silent');
    }

    private static function target(): NetTarget
    {
        return new NetTarget(
            rawInput: '93.184.216.34',
            host: '93.184.216.34',
            ips: ['93.184.216.34'],
            isDomain: false,
            isIp: true,
            verdict: GuardVerdict::allow(),
        );
    }
}
