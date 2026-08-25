<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Probes;

use BAGArt\TelegramBotNettools\Contracts\FetcherContract;
use BAGArt\TelegramBotNettools\Contracts\NettoolsProbeContract;
use BAGArt\TelegramBotNettools\Sources\FetchOutcome;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Support\HttpHopGuard;

/**
 * /http probe (RFC §7.13): single GET with a manually followed redirect chain
 * (≤3 hops, each timed and rendered), final status + protocol version,
 * content type/encoding/size (64 KB read cap), server banner line.
 * 4xx/5xx are results with hints, not failures; connection refused vs timeout
 * vs TLS failure are distinguished via the fetcher's error classification.
 *
 * Every redirect hop re-passes the SSRF verdict for the NEW host through the
 * hop guard and pins the connection to the approved IP — a public site cannot
 * 302 the probe into loopback/LAN/metadata space, and https is never
 * downgraded to http.
 */
final class HttpProbe implements NettoolsProbeContract
{
    public const string FLAG_SCHEME_HTTP = 'scheme_http';

    public const int MAX_REDIRECTS = 3;

    public const int BODY_CAP_BYTES = 65536;

    public function __construct(
        private readonly FetcherContract $fetcher,
        private readonly ?HttpHopGuard $hopGuard = null,
    ) {
    }

    public function name(): string
    {
        return 'http';
    }

    public function ttlSeconds(): int
    {
        return 300;
    }

    public function probe(NetTarget $target, ProbeOptions $options): ProbeResult
    {
        $host = $target->host;
        $ip = self::sameFamilyIp($target->ips, str_contains($host, ':'));
        $scheme = $options->flag(self::FLAG_SCHEME_HTTP) ? 'http' : 'https';
        $port = $scheme === 'https' ? 443 : 80;

        $chain = [];
        $url = "{$scheme}://{$host}/";
        $outcome = null;
        $pin = $ip !== null ? self::resolvePin($host, $port, $ip) : [];
        $blockedRedirect = null;

        for ($hop = 0; $hop <= self::MAX_REDIRECTS; $hop++) {
            $startedAt = microtime(true);
            $outcome = $this->fetcher->fetch($url, 'GET', 5, curlOptions: $pin);
            $elapsedMs = (int) round((microtime(true) - $startedAt) * 1000);

            if ($outcome->isTransportFailure()) {
                break;
            }

            $chain[] = ['url' => $url, 'status' => $outcome->status, 'ms' => $elapsedMs];

            $location = $outcome->header('Location');
            if ($outcome->status >= 300 && $outcome->status < 400 && is_string($location) && $hop < self::MAX_REDIRECTS) {
                $next = self::absoluteUrl($url, $location);
                if ($next === null || ! str_starts_with($next, 'http')) {
                    break;
                }

                $approval = $this->approveHop($target, $url, $next);
                if ($approval['reason'] !== null) {
                    // Visible block, never a silent abort (§5.2)
                    $blockedRedirect = ['url' => $next, 'reason' => $approval['reason']];

                    break;
                }

                $url = $next;
                $nextPort = self::portOf($next);
                $nextHost = (string) parse_url($next, PHP_URL_HOST);
                $pinnedIp = $approval['ip'];
                $pin = $pinnedIp !== null ? self::resolvePin($nextHost, $nextPort, $pinnedIp) : [];

                continue;
            }

            break;
        }

        return new ProbeResult(
            probe: $this->name(),
            fetchedAt: 0,
            latencyMs: 0,
            degradedSources: [],
            payload: $this->payload($target->host, $chain, $outcome, $blockedRedirect),
        );
    }

    /**
     * Redirect-target approval: same-host hops stay inside the already
     * approved resolution; any NEW host must re-pass the guard verdict.
     *
     * @return array{ip: ?string, reason: ?string}
     */
    private function approveHop(NetTarget $target, string $currentUrl, string $nextUrl): array
    {
        $currentHost = parse_url($currentUrl, PHP_URL_HOST);
        $nextHost = parse_url($nextUrl, PHP_URL_HOST);

        if (is_string($currentHost) && is_string($nextHost) && strcasecmp($currentHost, $nextHost) === 0) {
            return ['ip' => self::sameFamilyIp($target->ips, str_contains($nextHost, ':')), 'reason' => null];
        }

        if ($this->hopGuard === null) {
            return ['ip' => null, 'reason' => 'unguarded_cross_host_redirect'];
        }

        return $this->hopGuard->approve($nextUrl, parse_url($currentUrl, PHP_URL_SCHEME));
    }

    /** @return array<int, mixed> */
    private static function resolvePin(string $host, int $port, string $ip): array
    {
        return [CURLOPT_RESOLVE => ["{$host}:{$port}:{$ip}"]];
    }

    private static function portOf(string $url): int
    {
        return (int) (parse_url($url, PHP_URL_PORT) ?: (strtolower((string) parse_url($url, PHP_URL_SCHEME)) === 'http' ? 80 : 443));
    }

    /**
     * @param  list<array{url: string, status: int, ms: int}>  $chain
     * @param  array{url: string, reason: string}|null  $blockedRedirect
     * @return array<string, mixed>
     */
    private static function payload(string $host, array $chain, ?FetchOutcome $outcome, ?array $blockedRedirect = null): array
    {
        if ($outcome === null) {
            return ['host' => $host, 'error' => 'other', 'redirect_chain' => $chain, 'blocked_redirect' => $blockedRedirect];
        }

        if ($outcome->isTransportFailure()) {
            return [
                'host' => $host,
                'error' => $outcome->error ?? 'other',
                'redirect_chain' => $chain,
                'blocked_redirect' => $blockedRedirect,
            ];
        }

        $bodyLength = min(strlen($outcome->body), self::BODY_CAP_BYTES);
        $contentLength = filter_var($outcome->header('Content-Length'), FILTER_VALIDATE_INT);

        return [
            'host' => $host,
            'error' => null,
            'status' => $outcome->status,
            'http_version' => $outcome->protocolVersion,
            'content_type' => $outcome->header('Content-Type'),
            'content_encoding' => $outcome->header('Content-Encoding'),
            'bytes' => $bodyLength,
            'content_length' => $contentLength === false ? null : $contentLength,
            'truncated' => strlen($outcome->body) > self::BODY_CAP_BYTES && $contentLength === false,
            'server' => $outcome->header('Server'),
            'x_powered_by' => $outcome->header('X-Powered-By'),
            'final_url' => $chain === [] ? null : $chain[count($chain) - 1]['url'],
            'total_ms' => $chain === [] ? null : array_sum(array_map(static fn (array $h): int => $h['ms'], $chain)),
            'redirects' => max(0, count($chain) - 1),
            'redirect_chain' => $chain,
            'blocked_redirect' => $blockedRedirect,
            'findings' => self::findings($outcome, $chain),
        ];
    }

    private static function banner(FetchOutcome $outcome): ?string
    {
        $server = $outcome->header('Server');
        $poweredBy = $outcome->header('X-Powered-By');

        return match (true) {
            is_string($server) && is_string($poweredBy) => trim($server.' · '.$poweredBy),
            is_string($server), is_string($poweredBy) => $server ?? $poweredBy,
            default => null,
        };
    }

    /** Family-aware address pick (todo P3-8 seed): prefer v6 when the host is v6. @param list<string> $ips */
    public static function sameFamilyIp(array $ips, bool $preferV6): ?string
    {
        foreach ($ips as $ip) {
            $isV6 = str_contains($ip, ':');
            if ($isV6 === $preferV6) {
                return $ip;
            }
        }

        return $ips[0] ?? null;
    }

    private static function absoluteUrl(string $currentUrl, string $location): ?string
    {
        $location = trim($location);
        if ($location === '') {
            return null;
        }

        if (preg_match('#^https?://#i', $location) === 1) {
            return $location;
        }

        $parts = parse_url($currentUrl);
        if (! isset($parts['scheme'], $parts['host'])) {
            return null;
        }

        if (str_starts_with($location, '/')) {
            return $parts['scheme'].'://'.$parts['host'].$location;
        }

        $base = rtrim((string) parse_url($currentUrl, PHP_URL_PATH), '/');
        return $parts['scheme'].'://'.$parts['host'].rtrim($base, '/').'/'.$location;
    }
    /**
     * Deterministic /reco feed (RFC §8 Web/TLS table): compression and long
     * redirect chains. 4xx/5xx stay results, not findings.
     *
     * @param  list<array{url: string, status: int, ms: int}>  $chain
     * @return list<array{severity:'high'|'warn'|'info', id:string, detail:string}>
     */
    private static function findings(FetchOutcome $outcome, array $chain): array
    {
        $findings = [];

        if ($outcome->header('Content-Encoding') === null
            && preg_match('#text/|json|javascript#i', (string) $outcome->header('Content-Type')) === 1
            && $outcome->status < 300
            && strlen($outcome->body) > 1024) {
            $findings[] = ['severity' => 'info', 'id' => 'no_compression', 'detail' => 'text asset served uncompressed — enable brotli/gzip'];
        }

        if (count($chain) > 3) {
            $findings[] = ['severity' => 'info', 'id' => 'long_redirect_chain', 'detail' => 'redirect chain longer than 2 hops — shorten it'];
        }

        return $findings;
    }

}
