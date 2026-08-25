<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

use BAGArt\TelegramBotNettools\Contracts\FetcherContract;

/**
 * World ping via check-host.net free API (RFC §7.4): ICMP from ~5 vantage
 * nodes. Bounded blocking: ≤5 polls × 1s. Source down → graceful degrade.
 */
final class WorldPing
{
    private const int MAX_NODES = 5;

    public function __construct(private readonly FetcherContract $fetcher)
    {
    }

    /**
     * @return array{ok:bool, error:?string, nodes:list<array{node:string, region:string, ms:?int}>}
     */
    public function ping(string $host): array
    {
        $create = $this->fetcher->fetch(
            'https://check-host.net/check/ping?host='.rawurlencode($host).'&max_nodes='.self::MAX_NODES,
            'GET',
            5,
            ['Accept' => 'application/json'],
        );

        $payload = json_decode($create->body, true);
        if ($create->status !== 200 || ! is_array($payload) || ! isset($payload['request_id'])) {
            return ['ok' => false, 'error' => 'check-host.net unavailable — local result only', 'nodes' => []];
        }

        $regions = [];
        foreach ((array) ($payload['nodes'] ?? []) as $ip => $meta) {
            $regions[(string) $ip] = implode(', ', array_filter([
                is_string($meta[1] ?? null) ? $meta[1] : null,
                is_string($meta[0] ?? null) ? $meta[0] : null,
            ]));
        }

        for ($attempt = 0; $attempt < 5; $attempt++) {
            sleep(1);

            $result = $this->fetcher->fetch(
                'https://check-host.net/check-result/'.rawurlencode((string) $payload['request_id']),
                'GET',
                5,
                ['Accept' => 'application/json'],
            );
            $answers = json_decode($result->body, true);

            if (! is_array($answers)) {
                continue;
            }

            if ($this->settled($answers)) {
                return self::compose($regions, $answers);
            }
        }

        return ['ok' => false, 'error' => 'vantage nodes did not answer in time', 'nodes' => []];
    }

    /** @param array<string, mixed> $answers */
    private static function settled(array $answers): bool
    {
        foreach ($answers as $answer) {
            if (! is_array($answer) || ($answer[0] ?? null) === null) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param  array<string, string>  $regions
     * @return array{ok:bool, error:?string, nodes:list<array{node:string, region:string, ms:?int}>}
     */
    private static function compose(array $regions, array $answers): array
    {
        $nodes = [];
        foreach ($answers as $node => $answer) {
            $ping = is_array($answer[0] ?? null) ? (float) ($answer[0][0] ?? -1) : -1;

            $nodes[] = [
                'node' => (string) $node,
                'region' => $regions[(string) $node] ?? 'unknown',
                'ms' => $ping >= 0 ? (int) round($ping * 1000) : null,
            ];
        }

        return ['ok' => true, 'error' => null, 'nodes' => $nodes];
    }
}
