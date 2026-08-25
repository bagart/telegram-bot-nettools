<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Probes;

use BAGArt\TelegramBotNettools\Contracts\NettoolsProbeContract;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;

/**
 * /portscan TCP connect scan (RFC §7.11, admin-gated): top-100 ports,
 * 300ms connect timeout, ≤32 concurrent sockets, banner grab on open.
 * Loud disclaimer rendered by the command layer.
 */
final class PortScanProbe implements NettoolsProbeContract
{
    private const int MAX_CONCURRENT = 32;

    public const int WALL_CAP_SECONDS = 10;

    /** nmap-frequency-derived top ports (first 40 shown; full list in config override). */
    public const array TOP_PORTS = [
        80, 443, 22, 21, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900, 587,
        1025, 636, 113, 161, 50000, 81, 88, 8443, 465, 992, 563, 631, 646, 994, 8090, 23, 79, 7937, 7938, 512,
        513, 514, 990, 109, 953, 2121, 119, 1433, 1521, 2049, 2222, 2383, 3128, 3268, 3443, 3690, 4899, 5060, 5432, 5555,
        5666, 5984, 6379, 6667, 8000, 8008, 8009, 8081, 8089, 8181, 8888, 9000, 9001, 9090, 9200, 10000, 11211, 12345, 19150, 27017, 28017,
    ];

    /** @param \Closure(string $host, int $port): array{state:'open'|'closed'|'filtered', ms:?float, banner:?string} $connector */
    public function __construct(
        private readonly int $maxPorts = 100,
        private readonly ?\Closure $connector = null,
        ?\Closure $runProcess = null,
    ) {
        unset($runProcess);
    }

    public function name(): string
    {
        return 'portscan';
    }

    public function ttlSeconds(): int
    {
        return 0;
    }

    public function probe(NetTarget $target, ProbeOptions $options): ProbeResult
    {
        unset($options);
        $startedAt = microtime(true);
        $host = $target->ips[0] ?? $target->host;
        $ports = array_slice(self::TOP_PORTS, 0, min($this->maxPorts, count(self::TOP_PORTS)));

        $connect = $this->connector ?? self::streamConnector();

        $results = [];
        foreach ($ports as $i => $port) {
            $results[] = ['port' => $port, ...$connect($host, (int) $port)];

            // bounded-blocking politeness: yield every MAX_CONCURRENT batch
            if (($i + 1) % self::MAX_CONCURRENT === 0 && microtime(true) - $startedAt > self::WALL_CAP_SECONDS - 1) {
                break;
            }
        }

        return new ProbeResult(
            probe: $this->name(),
            fetchedAt: 0,
            latencyMs: (int) round((microtime(true) - $startedAt) * 1000),
            degradedSources: [],
            payload: [
                'host' => $target->host,
                'scanned' => count($results),
                'open' => array_values(array_filter($results, static fn (array $r): bool => $r['state'] === 'open')),
                'truncated' => count($results) < count($ports),
            ],
        );
    }

    public static function streamConnector(): \Closure
    {
        return static function (string $host, int $port): array {
            $socket = @stream_socket_client(
                "tcp://{$host}:{$port}",
                $errno,
                $errstr,
                0.3,
            );

            if ($socket === false) {
                return [
                    'state' => in_array($errno, [111, 61, 10061], true) ? 'closed' : 'filtered',
                    'ms' => null,
                    'banner' => null,
                ];
            }

            stream_set_timeout($socket, 0, 400000);
            $banner = fread($socket, 256);
            fclose($socket);

            return [
                'state' => 'open',
                'ms' => null,
                'banner' => is_string($banner) && trim($banner) !== '' ? trim((string) $banner) : null,
            ];
        };
    }
}
