<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Probes;

use BAGArt\TelegramBotNettools\Contracts\NettoolsProbeContract;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Sources\DnsAnswer;
use BAGArt\TelegramBotNettools\Sources\DnsClient;
use BAGArt\TelegramBotNettools\Sources\UdpDnsTransport;
use BAGArt\TelegramBotNettools\Support\SourceBreaker;

/**
 * /dns record matrix probe (RFC §7.2): A/AAAA/CNAME/MX/NS/TXT/SOA/CAA
 * against the configured resolvers, ≤2s per query type. Partial failures
 * are never silent — every unanswered type lands in degradedSources[].
 * TTL 1h (record-TTL-aware refinement is post-MVP).
 */
final class DnsProbe implements NettoolsProbeContract
{
    public const string FLAG_RECORD_TYPE = 'record_type';

    public const array DEFAULT_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA'];

    public function __construct(
        private readonly DnsClient $client,
        /** @var list<string> resolver IPs from config('tg-nettools.resolvers') */
        private readonly array $resolvers,
        private readonly ?SourceBreaker $breaker = null,
    ) {
    }

    public static function fromConfig(): self
    {
        return new self(
            client: new DnsClient(new UdpDnsTransport()),
            resolvers: self::defaultResolvers(),
        );
    }

    public function name(): string
    {
        return 'dns';
    }

    public function ttlSeconds(): int
    {
        return 3600;
    }

    public function probe(NetTarget $target, ProbeOptions $options): ProbeResult
    {
        $types = [$options->flags[self::FLAG_RECORD_TYPE] ?? null];
        $types = is_string($types[0]) && strtoupper($types[0]) !== '' ? [strtoupper($types[0])] : self::DEFAULT_TYPES;

        $records = [];
        $ttls = [];
        $statuses = [];
        $degraded = [];
        $dnssecAd = null;
        $authoritative = false;
        $timeout = max(1, min(5, $options->timeoutSeconds));

        foreach ($this->resolvers as $resolver) {
            if ($this->breaker !== null && ! $this->breaker->allow('dns:'.$resolver)) {
                $degraded['circuit:dns:'.$resolver] = true;

                continue;
            }

            foreach ($types as $type) {
                if (isset($records[$type])) {
                    continue; // first resolver wins — answers are consistent enough for the matrix
                }

                $answer = $this->client->query($resolver, $target->host, $type, $timeout);

                if ($answer === null) {
                    $degraded[$resolver] = true;

                    continue;
                }

                $dnssecAd ??= $answer->dnssecAd;
                $authoritative = $authoritative || $answer->authoritative;
                $statuses[$type] = $answer->statusName();

                if ($answer->rcode === DnsAnswer::NXDOMAIN && ! isset($statuses['zone'])) {
                    $statuses['zone'] = 'NXDOMAIN';
                }

                foreach ($answer->records as $typeName => $values) {
                    $records[$typeName] = array_values(array_unique([...($records[$typeName] ?? []), ...$values]));
                    $ttls[$typeName] = min($ttls[$typeName] ?? PHP_INT_MAX, $answer->ttls[$typeName] ?? PHP_INT_MAX);
                }
            }

            if ($records !== []) {
                $this->breaker?->recordSuccess('dns:'.$resolver);

                break; // primary resolver answered everything it could
            }

            $this->breaker?->recordFailure('dns:'.$resolver);
        }

        ksort($records);
        ksort($statuses);

        return new ProbeResult(
            probe: $this->name(),
            fetchedAt: 0,
            latencyMs: 0,
            degradedSources: array_keys($degraded),
            payload: [
                'host' => $target->host,
                'records' => $records,
                'ttls' => array_map(intval(...), array_filter($ttls, static fn (int $t): bool => $t !== PHP_INT_MAX)),
                'statuses' => $statuses,
                'dnssec_ad' => $dnssecAd,
                'authoritative' => $authoritative,
                'source_host' => implode(', ', $this->resolvers),
            ],
        );
    }


    /** @return list<string> */
    private static function defaultResolvers(): array
    {
        try {
            return array_values(array_filter(array_map(strval(...), (array) config('tg-nettools.resolvers', ['1.1.1.1', '8.8.8.8']))));
        } catch (\Throwable) {
            return ['1.1.1.1', '8.8.8.8'];
        }
    }
}
