<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Probes;

use BAGArt\TelegramBotNettools\Contracts\MmdbContract;
use BAGArt\TelegramBotNettools\Contracts\NettoolsProbeContract;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Sources\Port43TransportContract;
use BAGArt\TelegramBotNettools\Sources\RipestatSource;
use BAGArt\TelegramBotNettools\Support\AsnClassifier;
use BAGArt\TelegramBotNettools\Support\SourceBreaker;

/**
 * /asn probe (RFC §7.15): ASN card by AS number or IP input (owning-ASN
 * shortcut). mmdb → RIPEstat → Team Cymru port-43 chain; announced prefixes
 * (capped, v4/v6 split), top peers by power, type classification.
 */
final class AsnProbe implements NettoolsProbeContract
{
    public const string FLAG_ASN = 'asn';

    public const int PREFIX_CAP = 200;

    private const int PREFIX_SHOW = 50;

    private const int PEER_SAMPLE = 10;

    public function __construct(
        private readonly RipestatSource $ripestat,
        private readonly Port43TransportContract $port43,
        private readonly ?MmdbContract $mmdb = null,
        private readonly ?SourceBreaker $breaker = null,
    ) {
    }

    public function name(): string
    {
        return 'asn';
    }

    public function ttlSeconds(): int
    {
        return 21600;
    }

    public function probe(NetTarget $target, ProbeOptions $options): ProbeResult
    {
        $degraded = [];

        if (isset($options->flags[self::FLAG_ASN])) {
            $asn = self::normalizeAsn((string) $options->flags[self::FLAG_ASN]);
            if ($asn === null) {
                throw new \InvalidArgumentException("invalid AS number: {$options->flags[self::FLAG_ASN]}");
            }
        } else {
            $asn = $this->resolveAsnForIp($target->ips[0], $degraded);
        }

        $payload = [
            'input' => $target->host,
            'asn' => $asn,
            'org' => null,
            'country' => null,
            'registry' => null,
            'allocated' => null,
            'prefixes' => [],
            'prefix_counts' => ['v4' => 0, 'v6' => 0],
            'rpki' => null,
            'peers' => [],
            'type' => 'unknown',
            'source' => [],
        ];

        if ($asn === null) {
            $payload['not_announced'] = true;
            $payload['degraded'] = $degraded;

            return new ProbeResult(probe: $this->name(), fetchedAt: 0, latencyMs: 0, degradedSources: $degraded, payload: $payload);
        }

        $this->overview($asn, $payload, $degraded);
        $this->prefixes($asn, $payload, $degraded);
        $this->peers($asn, $payload, $degraded);

        if ($payload['source'] === []) {
            $this->cymru($payload, $degraded);
        }

        $payload['type'] = AsnClassifier::classify(is_scalar($payload['org']) ? (string) $payload['org'] : null);
        $payload['degraded'] = $degraded;

        return new ProbeResult(probe: $this->name(), fetchedAt: 0, latencyMs: 0, degradedSources: $degraded, payload: $payload);
    }

    /** @param list<string> $degraded */
    private function resolveAsnForIp(string $ip, array &$degraded): ?int
    {
        if ($this->mmdb !== null) {
            $record = $this->mmdb->asn($ip);
            if ($record !== null) {
                return $record['asn'];
            }
            $degraded[] = 'mmdb';
        }

        $info = $this->viaBreaker(RipestatSource::NAME, $degraded, fn (): ?array => $this->ripestat->networkInfo($ip));
        if ($info !== null && is_string($info['asn'] ?? null) && preg_match('/(\d+)/', $info['asn'], $m) === 1) {
            return (int) $m[1];
        }

        // Cymru last resort: verbose CSV "AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name"
        $raw = $this->port43->ask('whois.cymru.com', " -v {$ip}", 5);
        if ($raw !== null && preg_match('/^AS(\d+)\s*\|/mi', $raw, $m) === 1) {
            $degraded[] = 'cymru';

            return (int) $m[1];
        }

        return null;
    }

    /**
     * @param  array<string, mixed>  $payload
     * @param  list<string>  $degraded
     */
    private function overview(int $asn, array &$payload, array &$degraded): void
    {
        $body = $this->viaBreaker(RipestatSource::NAME, $degraded, fn (): ?array => $this->ripestat->prefixOverview('AS'.$asn));
        if ($body === null) {
            return;
        }

        $payload['source'][] = RipestatSource::NAME;

        foreach ((array) ($body['asns'] ?? []) as $entry) {
            if ((int) ($entry['asn'] ?? 0) === $asn) {
                $holder = is_string($entry['holder'] ?? null) ? $entry['holder'] : null;
                if ($payload['org'] === null && $holder !== null) {
                    $payload['org'] = $holder;
                }
            }
        }

        $block = (array) ($body['block'] ?? []);
        if ($payload['country'] === null && is_string($block['country'] ?? null)) {
            $payload['country'] = $block['country'];
        }
    }

    /**
     * @param  array<string, mixed>  $payload
     * @param  list<string>  $degraded
     */
    private function prefixes(int $asn, array &$payload, array &$degraded): void
    {
        $list = $this->viaBreaker(RipestatSource::NAME, $degraded, fn (): ?array => $this->ripestat->announcedPrefixes('AS'.$asn));
        if ($list === null) {
            return;
        }

        $payload['source'][] = RipestatSource::NAME;
        $list = array_slice($list, 0, self::PREFIX_CAP);

        $v4 = array_values(array_filter($list, static fn (string $p): bool => ! str_contains($p, ':')));
        $v6 = array_values(array_filter($list, static fn (string $p): bool => str_contains($p, ':')));
        sort($v4);
        sort($v6);

        $payload['prefixes'] = [...$v4, ...$v6];

        if ($v4 !== []) {
            $roa = $this->viaBreaker(RipestatSource::NAME, $degraded, fn (): ?array => [
                'status' => $this->ripestat->rpkiFor($v4[0]),
            ]);
            if (is_array($roa) && is_string($roa['status'] ?? null)) {
                $payload['rpki'] = $roa['status'];
            }
        }
        $payload['prefix_counts'] = [
            'v4' => count($v4),
            'v6' => count($v6),
            'total' => count($list),
        ];
    }

    /**
     * @param  array<string, mixed>  $payload
     * @param  list<string>  $degraded
     */
    private function peers(int $asn, array &$payload, array &$degraded): void
    {
        $neighbours = $this->viaBreaker(RipestatSource::NAME, $degraded, fn (): ?array => $this->ripestat->neighbours('AS'.$asn));
        if ($neighbours === null) {
            return;
        }

        $payload['source'][] = RipestatSource::NAME;

        $payload['peers'] = array_map(
            static fn (array $peer): array => [
                'asn' => $peer['asn'],
                'holder' => $peer['holder'],
                'power' => $peer['power'],
            ],
            array_slice($neighbours, 0, self::PEER_SAMPLE),
        );
    }

    /**
     * @param  array<string, mixed>  $payload
     * @param  list<string>  $degraded
     */
    private function cymru(array &$payload, array &$degraded): void
    {
        $asn = $payload['asn'];
        if (! is_int($asn)) {
            return;
        }

        $raw = $this->breakerGuardedCymru($degraded, " -v AS{$asn}");
        if ($raw === null) {
            return;
        }

        $payload['source'][] = 'cymru';

        // "AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name" — take the first data row
        foreach (explode("\n", $raw) as $line) {
            $columns = array_map(trim(...), explode('|', trim($line)));
            if (count($columns) >= 7 && strtoupper($columns[0]) === 'AS'.$asn) {
                $payload['country'] ??= $columns[3] !== 'NA' && $columns[3] !== '' ? $columns[3] : null;
                $payload['registry'] ??= $columns[4] !== 'NA' && $columns[4] !== '' ? $columns[4] : null;
                $payload['allocated'] ??= $columns[5] !== 'NA' && $columns[5] !== '' ? $columns[5] : null;
                $payload['org'] ??= $columns[6] !== '' && $columns[6] !== 'NA' ? $columns[6] : null;

                break;
            }
        }
    }

    /** @param list<string> $degraded */
    private function breakerGuardedCymru(array &$degraded, string $query): ?string
    {
        if ($this->breaker !== null && ! $this->breaker->allow('cymru')) {
            $degraded[] = 'circuit:cymru';

            return null;
        }

        $raw = $this->port43->ask('whois.cymru.com', $query, 5);
        if ($raw === null) {
            $degraded[] = 'cymru';
            $this->breaker?->recordFailure('cymru');

            return null;
        }

        $this->breaker?->recordSuccess('cymru');

        return $raw;
    }

    /**
     * @param  list<string>  $degraded
     * @template T
     *
     * @param  Closure(): T  $call
     * @return T|null
     */
    private function viaBreaker(string $source, array &$degraded, \Closure $call): mixed
    {
        if ($this->breaker !== null && ! $this->breaker->allow($source)) {
            $degraded[] = 'circuit:'.$source;

            return null;
        }

        $result = $call();

        if ($this->breaker !== null) {
            $result === null
                ? $this->breaker->recordFailure($source)
                : $this->breaker->recordSuccess($source);
        }

        if ($result === null) {
            $degraded[] = $source;
        }

        return $result;
    }

    public static function normalizeAsn(string $input): ?int
    {
        if (preg_match('/^\s*AS?(\d{1,10})\s*$/i', $input, $m) !== 1) {
            return null;
        }

        $asn = (int) $m[1];

        return $asn >= 1 && $asn <= 4294967295 ? $asn : null;
    }
}
