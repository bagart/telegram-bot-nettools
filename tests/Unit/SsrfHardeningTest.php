<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Unit;

use BAGArt\TelegramBotNettools\Contracts\DnsResolverContract;
use BAGArt\TelegramBotNettools\Probes\HttpProbe;
use BAGArt\TelegramBotNettools\Probes\SecHeadersProbe;
use BAGArt\TelegramBotNettools\Probes\SslProbe;
use BAGArt\TelegramBotNettools\Results\GuardVerdict;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Sources\PlatformHttp;
use BAGArt\TelegramBotNettools\Support\HttpHopGuard;
use BAGArt\TelegramBotNettools\Tests\Support\FakeProbeFetcher;
use BAGArt\TelegramBotNettools\Tests\Support\RawBodyApiClient;
use PHPUnit\Framework\TestCase;

/**
 * SSRF hardening regressions (todo P1-1/P1-2 gates): redirect-to-loopback
 * blocked in HttpProbe and PlatformHttp, https→http downgrade denied,
 * rebinding-style mixed answers blocked, Ssl/SecHeaders probes pinned to the
 * pipeline-resolved IP (no fresh DNS).
 */
final class SsrfHardeningTest extends TestCase
{
    public function test_http_probe_blocks_cross_host_redirect_to_loopback(): void
    {
        $fetcher = new FakeProbeFetcher([
            'https://example.com/' => [
                'status' => 302,
                'headers' => ['location' => 'https://127.0.0.1/steal'],
            ],
        ]);
        $probe = new HttpProbe($fetcher, new HttpHopGuard());

        $result = $probe->probe(self::target('example.com', ['203.0.113.10']), new ProbeOptions());

        self::assertSame('ssrf_blocked:loopback', $result->payload['blocked_redirect']['reason'] ?? null);
        self::assertSame('https://127.0.0.1/steal', $result->payload['blocked_redirect']['url'] ?? null);
        self::assertCount(1, $fetcher->curlOptionsSeen, 'blocked hop is never fetched');
    }

    public function test_http_probe_without_guard_fails_closed_on_cross_host_redirect(): void
    {
        $fetcher = new FakeProbeFetcher([
            'https://example.com/' => [
                'status' => 302,
                'headers' => ['location' => 'https://169.254.169.254/latest/meta-data/'],
            ],
        ]);
        $probe = new HttpProbe($fetcher);

        $result = $probe->probe(self::target('example.com', ['203.0.113.10']), new ProbeOptions());

        self::assertSame(
            'unguarded_cross_host_redirect',
            $result->payload['blocked_redirect']['reason'] ?? null,
            'missing guard must fail closed',
        );
    }

    public function test_platform_http_blocks_redirect_to_loopback(): void
    {
        $client = new RawBodyApiClient([
            'https://rdap.example/domain/x' => [
                'status' => 302,
                'headers' => ['Location' => 'http://169.254.169.254/latest/meta-data/'],
            ],
        ]);
        $http = new PlatformHttp($client, new HttpHopGuard());

        self::assertNull($http->getJson('https://rdap.example/domain/x', 5));
        self::assertCount(1, $client->requestedUrls, 'blocked hop is never fetched');
    }

    public function test_https_to_http_downgrade_is_denied_before_any_resolution(): void
    {
        // Public host — if resolution happened it would still pass; the
        // downgrade rule must fire first and offline.
        $resolver = new class () implements DnsResolverContract {
            public function resolveIps(string $host): array
            {
                throw new \LogicException('downgrade must be rejected without resolving');
            }
        };
        $guard = new HttpHopGuard($resolver);

        self::assertSame(['ip' => null, 'reason' => 'downgrade_https_to_http'], $guard->approve('http://example.com/', 'https'));
    }

    public function test_mixed_rebinding_answer_blocks_the_hop(): void
    {
        // First answer global, second loopback — classic rebinding shape.
        $resolver = new class () implements DnsResolverContract {
            public function resolveIps(string $host): array
            {
                return ['203.0.113.5', '127.0.0.1'];
            }
        };
        $guard = new HttpHopGuard($resolver);

        self::assertSame(
            ['ip' => null, 'reason' => 'ssrf_blocked:loopback'],
            $guard->approve('https://rebind.example/', 'https'),
        );
    }

    public function test_approved_hop_returns_pinned_ip(): void
    {
        $resolver = new class () implements DnsResolverContract {
            public function resolveIps(string $host): array
            {
                return ['198.51.100.7', '2001:db8::7'];
            }
        };

        self::assertSame(
            ['ip' => '198.51.100.7', 'reason' => null],
            (new HttpHopGuard($resolver))->approve('https://ok.example/', 'https'),
        );
    }

    /** P1-2: the inspector receives the pipeline-resolved pin, not the host to resolve. */
    public function test_ssl_probe_passes_pinned_ip_to_inspector(): void
    {
        $receivedPin = null;
        $probe = new SslProbe(static function (string $host, int $port, float $timeout, ?string $pinIp = null) use (&$receivedPin): array {
            $receivedPin = $pinIp;

            return ['has_tls' => false, 'error' => 'refused'];
        });

        $probe->probe(self::target('example.org', ['2001:db8::9', '203.0.113.9']), new ProbeOptions(timeoutSeconds: 3));

        self::assertSame('203.0.113.9', $receivedPin, 'family-aware pin: v4 host label → v4 address');
    }

    /** P1-2: every SecHeaders request carries a CURLOPT_RESOLVE pin for the resolved IP. */
    public function test_sec_headers_probe_pins_every_request(): void
    {
        $fetcher = new FakeProbeFetcher([
            'https://example.org/' => ['status' => 200, 'body' => '<html></html>', 'headers' => []],
        ]);
        $probe = new SecHeadersProbe($fetcher);

        $result = $probe->probe(self::target('example.org', ['203.0.113.77']), new ProbeOptions());

        self::assertNull($result->payload['error']);
        foreach ($fetcher->curlOptionsSeen as $options) {
            self::assertSame(
                ['example.org:443:203.0.113.77'],
                $options[CURLOPT_RESOLVE] ?? null,
                'request left without a pin — DNS-rebinding window',
            );
        }
    }

    private static function target(string $host, array $ips): NetTarget
    {
        return new NetTarget(
            rawInput: $host,
            host: $host,
            ips: $ips,
            isDomain: true,
            isIp: false,
            verdict: GuardVerdict::allow(),
        );
    }
}
