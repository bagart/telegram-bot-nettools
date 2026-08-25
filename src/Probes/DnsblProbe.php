<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Probes;

use BAGArt\TelegramBotNettools\Contracts\NettoolsProbeContract;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Sources\DnsClient;
use BAGArt\TelegramBotNettools\Support\SourceBreaker;

/**
 * /dnsbl A-query against ~10 major DNSBL zones (RFC §7.12, admin-gated).
 * NXDOMAIN = clean; an answer = listed. Queries run sequentially under a
 * hard wall cap ({@see self::WALL_CAP_SECONDS}): zones past the deadline and
 * timed-out zones are reported as degraded sources — never silently skipped.
 */
final class DnsblProbe implements NettoolsProbeContract
{
    public const int WALL_CAP_SECONDS = 6;
    public const array ZONES = [
        'zen.spamhaus.org',
        'b.barracudacentral.org',
        'bl.spamcop.net',
        'dnsbl.sorbs.net',
        'cbl.abuseat.org',
        'psbl.surriel.com',
        'spam.spamrats.com',
        'backscatter.spamrats.com',
        'ubl.unsubscore.net',
        'lashback.ubllist.com',
    ];

    public function __construct(
        private readonly DnsClient $dns,
        private readonly array $resolvers,
        private readonly int $timeoutSeconds = 2,
        private readonly ?SourceBreaker $breaker = null,
    ) {
    }

    public function name(): string
    {
        return 'dnsbl';
    }

    public function ttlSeconds(): int
    {
        return 1800;
    }

    public function probe(NetTarget $target, ProbeOptions $options): ProbeResult
    {
        unset($options);
        $startedAt = microtime(true);
        $ip = $target->ips[0] ?? null;

        if ($ip === null || ! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return new ProbeResult(
                probe: $this->name(),
                fetchedAt: 0,
                latencyMs: 0,
                degradedSources: [],
                payload: ['host' => $target->host, 'error' => 'ipv4-required', 'listed' => [], 'checked' => 0],
            );
        }

        $reversed = implode('.', array_reverse(explode('.', (string) $ip)));
        $resolver = $this->resolvers()[0] ?? '1.1.1.1';

        $listed = [];
        $degraded = [];
        $checked = 0;
        $timedOut = 0;

        foreach (self::ZONES as $zone) {
            if (microtime(true) - $startedAt > self::WALL_CAP_SECONDS) {
                // Wall budget spent: remaining zones degrade visibly, not silently
                $skipped = count(self::ZONES) - $checked - $timedOut;
                if ($skipped > 0) {
                    $degraded[] = "dnsbl:wall-cap({$skipped} zones)";
                }

                break;
            }

            $answer = $this->dns->query($resolver, "{$reversed}.{$zone}", 'A', $this->timeoutSeconds);
            if ($answer === null) {
                $timedOut++;
                $degraded[] = 'dnsbl:'.$zone;

                continue;
            }
            $checked++;

            // 127.255.255.x ranges are DNSBL "errors" (blocked query) — not listings
            foreach ((array) ($answer->records['A'] ?? []) as $record) {
                if (is_string($record) && ! str_starts_with($record, '127.255.255.')) {
                    $listed[] = ['zone' => $zone, 'answer' => $record];
                }
            }
        }

        if ($this->breaker !== null) {
            // every zone unanswered → source down; any answer → healthy
            if ($checked === 0) {
                $this->breaker->recordFailure('dnsbl');
            } else {
                $this->breaker->recordSuccess('dnsbl');
            }
        }

        return new ProbeResult(
            probe: $this->name(),
            fetchedAt: 0,
            latencyMs: (int) round((microtime(true) - $startedAt) * 1000),
            degradedSources: $degraded,
            payload: [
                'host' => $target->host,
                'ip' => $ip,
                'error' => null,
                'listed' => $listed,
                'checked' => $checked,
                'zones_total' => count(self::ZONES),
            ],
        );
    }

    /** @return list<string> */
    private function resolvers(): array
    {
        try {
            return array_values(array_filter(array_map(strval(...), (array) config('tg-nettools.resolvers', ['1.1.1.1', '8.8.8.8']))));
        } catch (\Throwable) {
            return ['1.1.1.1', '8.8.8.8'];
        }
    }
}
