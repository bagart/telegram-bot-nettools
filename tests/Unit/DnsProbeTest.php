<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Unit;

use BAGArt\TelegramBotNettools\Probes\DnsProbe;
use BAGArt\TelegramBotNettools\Results\GuardVerdict;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Sources\DnsClient;
use BAGArt\TelegramBotNettools\Tests\Support\FakeDnsTransport;
use PHPUnit\Framework\TestCase;

/**
 * DnsProbe matrix tests (RFC §7.2): record aggregation across the default
 * type set, per-type status surfacing, degraded resolvers never silent.
 */
final class DnsProbeTest extends TestCase
{
    private static function target(string $host = 'example.com'): NetTarget
    {
        return new NetTarget(
            rawInput: $host,
            host: $host,
            ips: ['93.184.216.34'],
            isDomain: true,
            isIp: false,
            verdict: GuardVerdict::allow(),
        );
    }

    public function test_matrix_aggregates_records_and_statuses(): void
    {
        $transport = new FakeDnsTransport();

        // one scripted answer per default-type query, in order:
        // A, AAAA, CNAME, MX, NS, TXT, SOA, CAA
        $transport->script(['udp' => FakeDnsTransport::response('example.com', 1, [
            ['type' => 1, 'ttl' => 3600, 'rdata' => inet_pton('93.184.216.34')],
        ])]);
        $transport->script(['udp' => FakeDnsTransport::response('example.com', 28, [
            ['type' => 28, 'rdata' => inet_pton('2606:2800:220:1:248:1893:25c8:1946')],
        ])]);
        $transport->script(['udp' => FakeDnsTransport::response('example.com', 5, [])]);
        $transport->script(['udp' => FakeDnsTransport::response('example.com', 15, [
            ['type' => 15, 'rdata' => pack('n', 10).FakeDnsTransport::name('mail.example.com')],
        ])]);
        $transport->script(['udp' => FakeDnsTransport::response('example.com', 2, [
            ['type' => 2, 'rdata' => FakeDnsTransport::name('ns1.example.com')],
            ['type' => 2, 'rdata' => FakeDnsTransport::name('ns2.example.com')],
        ])]);
        $spf = 'v=spf1 -all';
        $transport->script(['udp' => FakeDnsTransport::response('example.com', 16, [
            ['type' => 16, 'rdata' => chr(strlen($spf)).$spf],
        ])]);
        $soaRdata = FakeDnsTransport::name('ns1.example.com')
            .FakeDnsTransport::name('hostmaster.example.com')
            .pack('N5', 2026010101, 7200, 900, 1209600, 300);
        $transport->script(['udp' => FakeDnsTransport::response('example.com', 6, [
            ['type' => 6, 'rdata' => $soaRdata],
        ])]);
        $transport->script(['udp' => FakeDnsTransport::response('example.com', 257, [
            ['type' => 257, 'rdata' => "\x00"."\x05".'issue'.'letsencrypt.org'],
        ])]);

        $probe = new DnsProbe(new DnsClient($transport), ['192.0.2.53']);
        $result = $probe->probe(self::target(), new ProbeOptions(timeoutSeconds: 2));

        self::assertSame([], $result->degradedSources);
        self::assertSame(['93.184.216.34'], $result->payload['records']['A']);
        self::assertSame(3600, $result->payload['ttls']['A']);
        self::assertSame(['10 mail.example.com'], $result->payload['records']['MX']);
        self::assertSame(
            ['ns1.example.com', 'ns2.example.com'],
            $result->payload['records']['NS'],
        );
        self::assertSame(['v=spf1 -all'], $result->payload['records']['TXT']);
        self::assertSame('NOERROR', $result->payload['statuses']['A']);
        self::assertSame('NOERROR', $result->payload['statuses']['MX']);
        self::assertCount(8, $transport->udpQueries);
    }

    public function test_dead_resolver_lands_in_degraded_sources(): void
    {
        $transport = new FakeDnsTransport();

        $probe = new DnsProbe(new DnsClient($transport), ['192.0.2.53']);
        $result = $probe->probe(self::target(), new ProbeOptions(timeoutSeconds: 2));

        self::assertSame(['192.0.2.53'], $result->degradedSources);
        self::assertSame([], $result->payload['records']);
    }

    public function test_single_type_flag_narrows_the_matrix(): void
    {
        $transport = new FakeDnsTransport();
        $transport->script(['udp' => FakeDnsTransport::response('example.com', 15, [
            ['type' => 15, 'rdata' => pack('n', 10).FakeDnsTransport::name('mail.example.com')],
        ])]);

        $probe = new DnsProbe(new DnsClient($transport), ['192.0.2.53']);
        $options = new ProbeOptions(flags: [DnsProbe::FLAG_RECORD_TYPE => 'mx'], timeoutSeconds: 2);
        $result = $probe->probe(self::target(), $options);

        self::assertCount(1, $transport->udpQueries);
        self::assertArrayHasKey('MX', $result->payload['records']);
        self::assertArrayNotHasKey('A', $result->payload['records']);
    }
}
