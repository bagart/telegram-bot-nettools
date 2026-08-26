<?php

declare(strict_types=1);

/**
 * Nettools live smoke test (RFC §15 go-live gate).
 *
 * Runs every light probe against real network targets and prints a latency
 * table against the §15 budgets (light probes ≤ 6s wall, heavy ≤ 20s).
 * This is the executable part of the rollout checklist — run it on the
 * target host BEFORE enabling the module for users:
 *
 *   php misc/BAGArt/telegram-bot-nettools-module/tools/probe-smoke.php [--heavy] [--only=ip,dns]
 *
 * Constrained networks make every query wait its full timeout — expect a
 * complete run to take up to ~2 minutes when egress is degraded.
 *
 * Exit code 0 = every probe answered within budget; 1 = at least one hard
 * failure. Degraded sources are informational (single-provider flakiness is
 * an expected production state), transport-level errors are failures.
 */

use BAGArt\TelegramBot\Contracts\Outbound\OutboundCacheContract;
use BAGArt\TelegramBotNettools\Contracts\FetcherContract;
use BAGArt\TelegramBotNettools\Contracts\SourceHttpContract;
use BAGArt\TelegramBotNettools\Probes\{AsnProbe, DnsProbe, GeoAsnProbe, HttpProbe, MailAuditProbe, PingProbe, SecHeadersProbe, SslProbe, SubsProbe};
use BAGArt\TelegramBotNettools\Results\GuardVerdict;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Sources\CtLogSource;
use BAGArt\TelegramBotNettools\Sources\DnsClient;
use BAGArt\TelegramBotNettools\Sources\FetchOutcome;
use BAGArt\TelegramBotNettools\Sources\IpApiSource;
use BAGArt\TelegramBotNettools\Sources\RipestatSource;
use BAGArt\TelegramBotNettools\Sources\StreamPort43Transport;
use BAGArt\TelegramBotNettools\Support\HttpHopGuard;
use BAGArt\TelegramBotNettools\Sources\UdpDnsTransport;

require __DIR__.'/../../../../vendor/autoload.php';

/** @internal PSR-array cache — smoke runs are one-shot, nothing must persist. */
final class SmokeArrayCache implements OutboundCacheContract
{
    private array $items = [];

    public function incrementWithTtl(string $key, int $value, int $ttlSec): int
    {
        return $this->items[$key] = ($this->items[$key] ?? 0) + $value;
    }

    public function lock(string $key, int $ttlSec, ?string $owner = null): bool
    {
        return true; // single-process run — never busy
    }

    public function unlock(string $key, ?string $owner = null): void
    {
    }

    public function get(string $key): mixed
    {
        return $this->items[$key] ?? false;
    }

    public function put(string $key, mixed $value, int $ttlSec): void
    {
        $this->items[$key] = $value;
    }

    public function forget(string $key): void
    {
        unset($this->items[$key]);
    }
}

/** @internal Minimal JSON GET source for standalone runs. */
final class SmokeJsonHttp implements SourceHttpContract
{
    public function getJson(string $url, int $timeoutSeconds): ?array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT_MS => $timeoutSeconds * 1000,
            CURLOPT_CONNECTTIMEOUT_MS => $timeoutSeconds * 1000,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_USERAGENT => 'nettools-smoke/1.0',
            CURLOPT_HTTPHEADER => ['Accept: application/json'],
        ]);
        $body = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        if ($body === false || $status >= 400) {
            return null;
        }

        $decoded = json_decode((string) $body, true);

        return is_array($decoded) ? $decoded : null;
    }
}

/**
 * @internal Curl fetcher with the single-resolution invariant: each target
 * host is resolved once here and pinned via CURLOPT_RESOLVE.
 */
final class SmokeCurlFetcher implements FetcherContract
{
    public function __construct(private readonly DnsClient $dns)
    {
    }

    public function fetch(string $url, string $method, int $timeoutSeconds, array $headers = [], array $curlOptions = []): FetchOutcome
    {
        $parts = parse_url($url);
        $host = $parts['host'] ?? '';
        if ($host === '') {
            return new FetchOutcome(status: 0, body: '', error: 'bad url');
        }

        $port = $parts['port'] ?? (($parts['scheme'] ?? 'http') === 'https' ? 443 : 80);
        $pin = filter_var($host, FILTER_VALIDATE_IP) ? $host : null;
        if ($pin === null) {
            foreach (['1.1.1.1', '8.8.8.8'] as $resolver) {
                $answer = $this->dns->query($resolver, $host, 'A', min(3, $timeoutSeconds));
                $first = $answer?->records['A'][0] ?? null;
                if (is_string($first)) {
                    $pin = $first;

                    break;
                }
            }
            if ($pin === null) {
                return new FetchOutcome(status: 0, body: '', error: 'unresolved');
            }
        }

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT_MS => $timeoutSeconds * 1000,
            CURLOPT_FOLLOWLOCATION => false, // redirect chains stay explicit
            CURLOPT_RESOLVE => ["$host:$port:$pin"],
            CURLOPT_USERAGENT => 'nettools-smoke/1.0',
        ] + $curlOptions);
        $body = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        return new FetchOutcome(
            status: $body === false ? 0 : $status,
            body: (string) $body,
            error: $error !== '' ? $error : null,
        );
    }
}

$resolvers = ['1.1.1.1', '8.8.8.8'];
$dns = new DnsClient(new UdpDnsTransport());
$fetcher = new SmokeCurlFetcher($dns);
$cache = new SmokeArrayCache();
$http = new SmokeJsonHttp();
$capabilities = new \BAGArt\TelegramBotNettools\Support\CapabilityDetector($cache);
$guard = new HttpHopGuard();

$domainTarget = new NetTarget('example.com', 'example.com', ['93.184.216.34'], true, false, GuardVerdict::allow());
$ipTarget = new NetTarget('1.1.1.1', '1.1.1.1', ['1.1.1.1'], false, true, GuardVerdict::allow());
$httpsTarget = new NetTarget('https://example.com', 'example.com', ['93.184.216.34'], true, false, GuardVerdict::allow());

$probes = [
    'ip' => [$ipTarget, new GeoAsnProbe(new IpApiSource($http), new RipestatSource($http), $dns, $resolvers)],
    'asn' => [$ipTarget, new AsnProbe(new RipestatSource($http), new StreamPort43Transport())],
    'dns' => [$domainTarget, new DnsProbe($dns, $resolvers)],
    'mail' => [$domainTarget, new MailAuditProbe($dns, $resolvers, 2)],
    'subs' => [$domainTarget, new SubsProbe(new CtLogSource($http), $dns, $resolvers, 2)],
    'http' => [$httpsTarget, new HttpProbe(fetcher: $fetcher, hopGuard: $guard)],
    'sec' => [$httpsTarget, new SecHeadersProbe($fetcher)],
    'ssl' => [$httpsTarget, new SslProbe(SslProbe::selfInspector())],
];

$argv = $_SERVER['argv'] ?? [];

$isHeavy = in_array('--heavy', $argv, true);
if ($isHeavy) {
    $probes['ping'] = [$ipTarget, new PingProbe($capabilities)];
}

foreach ($argv as $arg) {
    if (str_starts_with((string) $arg, '--only=')) {
        $probes = array_intersect_key($probes, array_flip(explode(',', substr((string) $arg, 7))));
    }
}

$results = [];
$failures = 0;
foreach ($probes as $name => [$target, $probe]) {
    $startedAt = microtime(true);
    try {
        $outcome = $probe->probe($target, new ProbeOptions(timeoutSeconds: 6));
        $ms = (int) round((microtime(true) - $startedAt) * 1000);
        $degraded = $outcome->degradedSources;
        $results[] = [$name, $ms, $degraded === [] ? 'ok' : 'ok · degraded: '.implode(',', $degraded)];

        // §15 budget: light probes ≤ 6s wall
        if ($ms > 6000) {
            $failures++;
            $results[count($results) - 1][2] .= ' · OVER BUDGET';
        }
    } catch (\Throwable $e) {
        $ms = (int) round((microtime(true) - $startedAt) * 1000);
        $results[] = [$name, $ms, 'FAIL: '.mb_substr($e->getMessage(), 0, 60)];
        $failures++;
    }
}

printf("%-8s %8s  %s\n", 'PROBE', 'MS', 'STATUS');
foreach ($results as [$name, $ms, $status]) {
    printf("%-8s %8d  %s\n", $name, $ms, $status);
}
printf("\n%d probe(s), %d failure(s)\n", count($results), $failures);

exit($failures === 0 ? 0 : 1);
