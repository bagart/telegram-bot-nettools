<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Unit;

use BAGArt\TelegramBotNettools\Contracts\NettoolsProbeContract;
use BAGArt\TelegramBotNettools\NettoolsServices;
use BAGArt\TelegramBotNettools\Commands\WhoisCommand;
use BAGArt\TelegramBotNettools\Tests\Support\FakeBotHarness;
use BAGArt\TelegramBotNettools\Tests\Support\FakeDnsTransport;
use BAGArt\TelegramBotNettools\Tests\Support\FakeHttpSource;
use BAGArt\TelegramBotNettools\Tests\Support\FakeLocker;
use BAGArt\TelegramBotNettools\Tests\Support\FakeOutboundCacheFactory;
use BAGArt\TelegramBotNettools\Tests\Support\FakeProbeFetcher;
use BAGArt\TelegramBotNettools\Tests\Support\FakePort43Transport;
use PHPUnit\Framework\TestCase;

/**
 * Factory-path wiring (todo.nettools P5-1 / P0-1 gate): every probe factory
 * on NettoolsServices must construct and smoke-run over fakes — catches
 * wiring drift that probe-level tests with hand-injected transports miss
 * (the P0-1 whois TypeError class).
 */
final class FactoryWiringTest extends TestCase
{
    private const string BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';

    private const string RDAP_ORG = 'https://rdap.publicinterestregistry.org/rdap/domain/example.org';

    public function test_every_probe_factory_constructs_through_services(): void
    {
        $services = $this->services();

        $probes = [
            'whois' => $services->whoisProbe(),
            'dns' => $services->dnsProbe(),
            'ip' => $services->geoProbe(),
            'ping' => $services->pingProbe(),
            'trace' => $services->traceProbe(),
            'http' => $services->httpProbe(),
            'asn' => $services->asnProbe(),
        ];

        foreach ($probes as $name => $probe) {
            self::assertInstanceOf(NettoolsProbeContract::class, $probe);
            self::assertSame($name, $probe->name());
        }
    }

    public function test_factory_whois_probe_runs_over_fakes(): void
    {
        $http = new FakeHttpSource([
            self::BOOTSTRAP_URL => [
                'services' => [[['org'], ['https://rdap.publicinterestregistry.org/rdap']]],
            ],
            self::RDAP_ORG => $this->rdapBody(),
        ]);

        $result = $this->services($http)->whoisProbe()->probe(
            $this->target('example.org'),
            new \BAGArt\TelegramBotNettools\Results\ProbeOptions(timeoutSeconds: 5),
        );

        self::assertSame('RegistrarOps, Inc.', $result->payload['registrar_name']);
        self::assertSame([], $result->degradedSources);
    }

    public function test_factory_dns_probe_resolves_scripted_answers(): void
    {
        $dns = new FakeDnsTransport();
        $dns->script(['udp' => FakeDnsTransport::response('example.com', 1, [
            ['type' => 1, 'ttl' => 3600, 'rdata' => inet_pton('93.184.216.34')],
        ])]);

        $result = $this->services(dns: $dns)->dnsProbe()->probe(
            $this->target('example.com'),
            new \BAGArt\TelegramBotNettools\Results\ProbeOptions(timeoutSeconds: 2),
        );

        self::assertSame(['93.184.216.34'], $result->payload['records']['A']);
    }

    public function test_factory_geo_probe_falls_back_to_ipapi_fixture(): void
    {
        $http = new FakeHttpSource([
            'http://ip-api.com/json/93.184.216.34?fields=status,message,country,regionName,city,lat,lon,isp,org,as,asname,mobile,proxy,hosting,query' => [
                'status' => 'success',
                'country' => 'US',
                'as' => 'AS15169 GOOGLE',
                'org' => 'Google LLC',
            ],
        ]);

        $result = $this->services($http)->geoProbe()->probe(
            $this->target('93.184.216.34', isIp: true),
            new \BAGArt\TelegramBotNettools\Results\ProbeOptions(timeoutSeconds: 3),
        );

        self::assertSame('US', $result->payload['country']);
        self::assertSame(15169, $result->payload['asn']);
    }

    /**
     * The P0-1 end-to-end gate: /whois through WhoisCommand →
     * NettoolsServices::whoisProbe() — previously a construction TypeError.
     */
    public function test_whois_command_flows_through_services_factory(): void
    {
        $harness = FakeBotHarness::create([
            'https://rdap.org/ip/93.184.216.34' => $this->rdapBody(),
        ]);

        $whois = new WhoisCommand($harness->sender, $harness->services, $harness->context);
        $whois->execute($harness->botConfig(), '100', 42, '93.184.216.34');

        self::assertStringContainsString('RegistrarOps, Inc.', $harness->lastText());
        self::assertSame(WhoisCommand::WEIGHT, $harness->services->quota->usedByUser(100, 42));
    }

    private function services(?FakeHttpSource $http = null, ?FakeDnsTransport $dns = null): NettoolsServices
    {
        return NettoolsServices::forTests(
            cache: FakeOutboundCacheFactory::create(),
            locker: new FakeLocker(),
            http: $http ?? new FakeHttpSource(),
            fetcher: new FakeProbeFetcher(),
            dnsTransport: $dns ?? new FakeDnsTransport(),
            port43: new FakePort43Transport(null),
        );
    }

    private function rdapBody(): array
    {
        return [
            'ldhName' => 'EXAMPLE.ORG',
            'status' => ['client transfer prohibited'],
            'events' => [
                ['eventAction' => 'registration', 'eventDate' => '1995-08-31T04:00:00Z'],
                ['eventAction' => 'expiration', 'eventDate' => '2026-08-30T04:00:00Z'],
            ],
            'nameservers' => [['ldhName' => 'A.IANA-SERVERS.NET']],
            'entities' => [
                [
                    'roles' => ['registrar'],
                    'vcardArray' => ['vcard', [['fn', [], 'text', 'RegistrarOps, Inc.']]],
                ],
            ],
        ];
    }

    private static function target(string $host, bool $isIp = false): \BAGArt\TelegramBotNettools\Results\NetTarget
    {
        return new \BAGArt\TelegramBotNettools\Results\NetTarget(
            rawInput: $host,
            host: $host,
            ips: [$host],
            isDomain: ! $isIp,
            isIp: $isIp,
            verdict: \BAGArt\TelegramBotNettools\Results\GuardVerdict::allow(),
        );
    }
}
