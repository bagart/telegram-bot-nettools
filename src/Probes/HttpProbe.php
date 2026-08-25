<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Probes;

use BAGArt\TelegramBotNettools\Contracts\FetcherContract;
use BAGArt\TelegramBotNettools\Contracts\NettoolsProbeContract;
use BAGArt\TelegramBotNettools\Sources\FetchOutcome;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;

/**
 * /http probe (RFC §7.13): single GET with a manually followed redirect chain
 * (≤3 hops, each timed and rendered), final status + protocol version,
 * content type/encoding/size (64 KB read cap), server banner line.
 * 4xx/5xx are results with hints, not failures; connection refused vs timeout
 * vs TLS failure are distinguished via the fetcher's error classification.
 */
final class HttpProbe implements NettoolsProbeContract
{
    public const string FLAG_SCHEME_HTTP = 'scheme_http';

    public const int MAX_REDIRECTS = 3;

    public const int BODY_CAP_BYTES = 65536;

    public function __construct(private readonly FetcherContract $fetcher)
    {
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

        // Pin the connection to the guard-approved IP — no second resolution
        // (single-resolution invariant §4.3)
        $pin = $ip !== null ? [CURLOPT_RESOLVE => ["{$host}:{$port}:{$ip}"]] : [];

        $chain = [];
        $url = "{$scheme}://{$host}/";
        $outcome = null;

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
                $url = $next;

                continue;
            }

            break;
        }

        return new ProbeResult(
            probe: $this->name(),
            fetchedAt: 0,
            latencyMs: 0,
            degradedSources: [],
            payload: $this->payload($target->host, $chain, $outcome),
        );
    }

    /**
     * @param  list<array{url: string, status: int, ms: int}>  $chain
     * @return array<string, mixed>
     */
    private static function payload(string $host, array $chain, ?FetchOutcome $outcome): array
    {
        if ($outcome === null) {
            return ['host' => $host, 'error' => 'other', 'redirect_chain' => $chain];
        }

        if ($outcome->isTransportFailure()) {
            return [
                'host' => $host,
                'error' => $outcome->error ?? 'other',
                'redirect_chain' => $chain,
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

    /** @param list<string> $ips */
    private static function sameFamilyIp(array $ips, bool $preferV6): ?string
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
}
