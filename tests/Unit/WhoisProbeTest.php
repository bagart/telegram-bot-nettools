<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Unit;

use BAGArt\TelegramBotNettools\Contracts\Exceptions\UpstreamUnavailableException;
use BAGArt\TelegramBotNettools\Probes\WhoisProbe;
use BAGArt\TelegramBotNettools\Results\GuardVerdict;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Tests\Support\FakeHttpSource;
use BAGArt\TelegramBotNettools\Tests\Support\FakeOutboundCacheFactory;
use BAGArt\TelegramBotNettools\Tests\Support\FakePort43Transport;
use PHPUnit\Framework\TestCase;

/**
 * WhoisProbe fixture tests (RFC §7.1): RDAP-first, port-43 fallback, one
 * referral hop, degraded-source surfacing, homograph hint, JSON round-trip.
 */
final class WhoisProbeTest extends TestCase
{
    private const string RDAP_ORG = 'https://rdap.publicinterestregistry.org/rdap/domain/example.org';

    private const string BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';

    private function bootstrapBody(): array
    {
        return [
            'services' => [
                [['org'], ['https://rdap.publicinterestregistry.org/rdap']],
                [['xyz'], ['https://rdap.registry.example']],
            ],
        ];
    }

    private function probeWith(FakeHttpSource $http, ?FakePort43Transport $port43 = null): WhoisProbe
    {
        return new WhoisProbe(
            $http,
            FakeOutboundCacheFactory::create(),
            $port43 ?? new FakePort43Transport(null),
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
                ['eventAction' => 'last changed', 'eventDate' => '2025-08-01T04:00:00Z'],
            ],
            'nameservers' => [
                ['ldhName' => 'A.IANA-SERVERS.NET'],
                ['ldhName' => 'B.IANA-SERVERS.NET'],
            ],
            'secureDNS' => ['delegationSigned' => true],
            'entities' => [
                [
                    'roles' => ['registrar'],
                    'publicIds' => [['type' => 'IANA Registrar ID', 'identifier' => '1913']],
                    'vcardArray' => ['vcard', [['fn', [], 'text', 'RegistrarOps, Inc.']]],
                ],
                [
                    'roles' => ['abuse'],
                    'vcardArray' => ['vcard', [['email', [], 'text', 'abuse@registrarops.example']]],
                ],
                [
                    'roles' => ['registrant'],
                    'remarks' => [['title' => 'REDACTED FOR PRIVACY', 'description' => ['GDPR redaction']]],
                ],
            ],
        ];
    }

    private static function target(string $host, bool $isIp = false): NetTarget
    {
        return new NetTarget(
            rawInput: $host,
            host: $host,
            ips: [$host],
            isDomain: ! $isIp,
            isIp: $isIp,
            verdict: GuardVerdict::allow(),
        );
    }

    public function test_rdap_domain_answer_is_normalized(): void
    {
        $http = new FakeHttpSource([
            self::BOOTSTRAP_URL => $this->bootstrapBody(),
            self::RDAP_ORG => $this->rdapBody(),
        ]);
        $result = $this->probeWith($http)->probe($this->target('example.org'), new ProbeOptions(timeoutSeconds: 5));

        self::assertSame('rdap.publicinterestregistry.org', $result->payload['source_host']);
        self::assertSame('RegistrarOps, Inc.', $result->payload['registrar_name']);
        self::assertSame('1913', $result->payload['registrar_iana_id']);
        self::assertSame('1995-08-31', $result->payload['created_at']);
        self::assertSame('2026-08-30', $result->payload['expires_at']);
        self::assertTrue($result->payload['dnssec']);
        self::assertSame(['a.iana-servers.net', 'b.iana-servers.net'], $result->payload['nameservers']);
        self::assertSame('abuse@registrarops.example', $result->payload['abuse_email']);
        self::assertContains('registrant identity', $result->payload['redacted_fields']);
        self::assertSame([], $result->degradedSources);
    }

    public function test_thin_registry_referral_is_followed_once(): void
    {
        $thinUrl = 'https://rdap.registry.example/domain/example.xyz';
        $registrarUrl = 'https://rdap.registrar.example/domain/example.xyz';

        $thin = $this->rdapBody();
        $thin['links'] = [['rel' => 'related', 'href' => $registrarUrl, 'type' => 'application/rdap+json']];
        $full = $this->rdapBody();

        $http = new FakeHttpSource([
            self::BOOTSTRAP_URL => $this->bootstrapBody(),
            $thinUrl => $thin,
            $registrarUrl => $full,
        ]);
        $result = $this->probeWith($http)->probe($this->target('example.xyz'), new ProbeOptions(timeoutSeconds: 5));

        self::assertSame([$thinUrl, $registrarUrl], array_slice($http->requestedUrls, -2), 'exactly one referral hop');
        self::assertSame('rdap.registrar.example', $result->payload['source_host']);
    }

    public function test_rdap_failure_degrades_to_port43(): void
    {
        $port43 = new FakePort43Transport(
            "Domain Name: example.org\r\nRegistry Expiry Date: 2027-01-15T04:00:00Z\r\nDNSSEC: signedDelegation\r\n",
        );
        $probe = new WhoisProbe(new FakeHttpSource(), FakeOutboundCacheFactory::create(), $port43);

        $result = $probe->probe($this->target('unknown-tld-xyzzy123.example'), new ProbeOptions(timeoutSeconds: 5));

        self::assertSame(['rdap'], $result->degradedSources, 'RDAP failure is a visible warning, never silent');
        self::assertSame('2027-01-15', $result->payload['expires_at']);
        self::assertTrue($result->payload['dnssec']);
    }

    public function test_all_sources_dead_raises_upstream_unavailable(): void
    {
        $probe = new WhoisProbe(
            new FakeHttpSource(),
            FakeOutboundCacheFactory::create(),
            new FakePort43Transport(null),
        );

        $this->expectException(UpstreamUnavailableException::class);

        $probe->probe($this->target('dead.example'), new ProbeOptions(timeoutSeconds: 2));
    }

    public function test_ip_target_uses_redirector_only(): void
    {
        $ip = '93.184.216.34';
        $http = new FakeHttpSource(['https://rdap.org/ip/'.$ip => $this->rdapBody()]);
        $result = $this->probeWith($http)->probe($this->target($ip, isIp: true), new ProbeOptions(timeoutSeconds: 5));

        self::assertSame(['https://rdap.org/ip/'.$ip], $http->requestedUrls);
        self::assertSame('rdap.org', $result->payload['source_host']);
    }

    public function test_result_json_round_trip_is_lossless(): void
    {
        $probe = $this->probeWith(new FakeHttpSource([
            self::BOOTSTRAP_URL => $this->bootstrapBody(),
            self::RDAP_ORG => $this->rdapBody(),
        ]));

        $original = $probe->probe($this->target('example.org'), new ProbeOptions(timeoutSeconds: 5));
        $restored = ProbeResult::fromArray(
            json_decode(json_encode($original->toArray(), JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR),
        );

        self::assertSame($original->toArray(), $restored->toArray(), 'cache-purity rule: state-only DTO');
    }
}
