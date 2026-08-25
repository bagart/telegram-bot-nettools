<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Probes;

use BAGArt\TelegramBot\Contracts\Outbound\OutboundCacheContract;
use BAGArt\TelegramBotNettools\Contracts\Exceptions\UpstreamUnavailableException;
use BAGArt\TelegramBotNettools\Contracts\NettoolsProbeContract;
use BAGArt\TelegramBotNettools\Contracts\SourceHttpContract;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Sources\Port43TransportContract;
use BAGArt\TelegramBotNettools\Sources\Port43WhoisClient;
use BAGArt\TelegramBotNettools\Sources\RdapClient;
use BAGArt\TelegramBotNettools\Sources\StreamPort43Transport;
use BAGArt\TelegramBotNettools\Support\HomographCheck;
use BAGArt\TelegramBotNettools\Support\SourceBreaker;

/**
 * /whois probe (RFC §7.1): RDAP-first, port-43 fallback, one referral hop,
 * redaction-aware contacts. TTL 24h (expiry countdown accurate ±1d).
 *
 * Partial results are never silent: every failed source lands in
 * degradedSources[]. Both sources empty + NXDOMAIN-ish → availability hint
 * instead of a hard error.
 */
final class WhoisProbe implements NettoolsProbeContract
{
    public function __construct(
        private readonly SourceHttpContract $http,
        private readonly OutboundCacheContract $cache,
        private readonly Port43TransportContract $port43 = new StreamPort43Transport(),
        private readonly ?SourceBreaker $breaker = null,
    ) {
    }

    public function name(): string
    {
        return 'whois';
    }

    public function ttlSeconds(): int
    {
        return 86400;
    }

    /** RDAP ≤5s, port-43 ≤8s (config timeouts). */
    public function probe(NetTarget $target, ProbeOptions $options): ProbeResult
    {
        $startedAt = microtime(true);
        $degraded = [];

        $rdapTimeout = max(1, min(5, $options->timeoutSeconds));
        $port43Timeout = max(1, $options->timeoutSeconds);

        $payload = null;

        if ($target->isIp) {
            $payload = $this->viaBreaker('rdap', $degraded, fn (): array => $this->fromRdapIp($target->host, $rdapTimeout));
        } else {
            $payload = $this->viaBreaker('rdap', $degraded, fn (): array => $this->fromRdapDomain($target->host, $rdapTimeout));
            $payload ??= $this->viaBreaker('whois43', $degraded, fn (): array => $this->fromPort43($target->host, $port43Timeout));
        }

        if ($payload === null) {
            throw new UpstreamUnavailableException('whois', 'no source answered for '.$target->host);
        }

        $payload['hints'] = array_filter([
            'homograph' => HomographCheck::warningFor($target->host),
        ], static fn (?string $v): bool => $v !== null);
        if ($degraded !== []) {
            $payload['degraded'] = $degraded;
        }
        ksort($payload);

        return new ProbeResult(
            probe: $this->name(),
            fetchedAt: 0,
            latencyMs: (int) round((microtime(true) - $startedAt) * 1000),
            degradedSources: $degraded,
            payload: $payload,
        );
    }

    /**
     * Breaker-guarded source run: open circuit → skip with a degraded note;
     * empty answer → failure recorded, visible warning appended.
     *
     * @param  list<string>  $degraded
     * @param  Closure(): array{0: array<string, mixed>|null, 1: ?string}  $fetch
     */
    private function viaBreaker(string $source, array &$degraded, \Closure $fetch): ?array
    {
        if ($this->breaker !== null && ! $this->breaker->allow($source)) {
            $degraded[] = 'circuit:'.$source;

            return null;
        }

        [$payload] = $fetch();

        if ($payload === null) {
            $degraded[] = $source;
            $this->breaker?->recordFailure($source);

            return null;
        }

        $this->breaker?->recordSuccess($source);

        return $payload;
    }

    /** @return array{0: array<string, mixed>|null, 1: ?string} */
    private function fromRdapDomain(string $host, int $timeout): array
    {
        $client = new RdapClient($this->http, $this->cache);
        $answer = $client->lookupDomain($host, $timeout);

        return $answer === null
            ? [null, null]
            : [self::merge(RdapClient::normalize($answer['data']), $answer['server']), 'rdap'];
    }

    /** @return array{0: array<string, mixed>|null, 1: ?string} */
    private function fromRdapIp(string $ip, int $timeout): array
    {
        $client = new RdapClient($this->http, $this->cache);
        $answer = $client->lookupIp($ip, $timeout);

        return $answer === null
            ? [null, null]
            : [self::merge(RdapClient::normalize($answer['data']), $answer['server']), 'rdap'];
    }

    /**
     * @return array{0: array<string, mixed>|null, 1: ?string}
     */
    private function fromPort43(string $host, int $timeout): array
    {
        $client = new Port43WhoisClient($this->port43);
        $answer = $client->lookup($host, $timeout);

        return $answer === null
            ? [null, null]
            : [self::merge(Port43WhoisClient::normalize($answer['text']), $answer['server']), 'port43'];
    }

    /**
     * @param  array<string, mixed>  $fields
     */
    private static function merge(array $fields, string $sourceHost): array
    {
        $fields['source_host'] = strtolower((string) parse_url($sourceHost, PHP_URL_HOST) ?: $sourceHost);

        return $fields;
    }
}
