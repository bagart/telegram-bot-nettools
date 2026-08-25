<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Probes;

use BAGArt\TelegramBotNettools\Contracts\Exceptions\CapabilityMissingException;
use BAGArt\TelegramBotNettools\Contracts\NettoolsProbeContract;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Support\CapabilityDetector;

/**
 * /ping probe (RFC §7.4): system ping binary (argv-safe, resolved-IP only),
 * parsed loss/latency/jitter/TTLs; no binary → TCP-connect timing fallback
 * against 443/80. Measurements are never cached (ttlSeconds = 0).
 */
final class PingProbe implements NettoolsProbeContract
{
    private const int DEADLINE_SECONDS = 4;

    private const int TCP_ATTEMPTS = 3;

    /** @var (Closure(list<string> $argv): array{exit: int, out: string})|null */
    private readonly ?\Closure $runProcess;

    /** @var (Closure(string $ip, int $port, int $timeoutSeconds): float|null)|null returns connect ms or null */
    private readonly ?\Closure $tcpConnect;

    public function __construct(
        private readonly CapabilityDetector $capabilities,
        private readonly int $packets = 4,
        ?\Closure $runProcess = null,
        ?\Closure $tcpConnect = null,
    ) {
        $this->runProcess = $runProcess;
        $this->tcpConnect = $tcpConnect;
    }

    public function name(): string
    {
        return 'ping';
    }

    public function ttlSeconds(): int
    {
        return 0;
    }

    public function probe(NetTarget $target, ProbeOptions $options): ProbeResult
    {
        $ip = $target->ips[0];

        if ($this->capabilities->pingAvailable()) {
            return $this->icmp($ip);
        }

        return $this->tcp($target, $ip);
    }

    /** @param list<string> $degraded */
    private function icmp(string $ip): ProbeResult
    {
        $argv = ['ping', '-n', '-c', (string) $this->packets, '-w', (string) self::DEADLINE_SECONDS, '--', $ip];
        if (str_contains($ip, ':')) {
            array_splice($argv, 1, 0, ['-6']);
        }

        ['exit' => $exit, 'out' => $out] = $this->run($argv);

        [$sent, $received, $lossPct] = self::parseSummary($out);
        $rtt = self::parseRttLine($out);
        $replies = self::parseReplies($out);

        $unreachable = $received === 0 && count($replies) === 0;

        return new ProbeResult(
            probe: $this->name(),
            fetchedAt: 0,
            latencyMs: 0,
            degradedSources: [],
            payload: [
                'mode' => 'icmp',
                'target_ip' => $ip,
                'sent' => $sent,
                'received' => max($received, count($replies)),
                'loss_pct' => $lossPct ?? ($unreachable ? 100.0 : null),
                'min_ms' => $rtt['min'] ?? null,
                'avg_ms' => $rtt['avg'] ?? null,
                'max_ms' => $rtt['max'] ?? null,
                'jitter_ms' => $rtt['mdev'] ?? null,
                'replies' => $replies,
                'binary_exit' => $exit,
                'unreachable' => $unreachable,
            ],
        );
    }

    /**
     * @return array{0: ?int, 1: ?int, 2: ?float}
     */
    private static function parseSummary(string $out): array
    {
        if (preg_match('/(\d+) packets transmitted,\s*(\d+)(?: received)?(?:,[^%]*)?([\d.]+)% packet loss/', $out, $m) === 1) {
            return [(int) $m[1], (int) $m[2], (float) $m[3]];
        }

        if (preg_match('/([\d.]+)% packet loss/', $out, $m) === 1) {
            return [null, null, (float) $m[1]];
        }

        return [null, null, null];
    }

    /**
     * @return array{min: float, avg: float, max: float, mdev: float}|null
     */
    private static function parseRttLine(string $out): ?array
    {
        if (preg_match('/=\s*([\d.]+)\/([\d.]+)\/([\d.]+)\/([\d.]+)\s*ms/', $out, $m) !== 1) {
            return null;
        }

        return [
            'min' => (float) $m[1],
            'avg' => (float) $m[2],
            'max' => (float) $m[3],
            'mdev' => (float) $m[4],
        ];
    }

    /**
     * @return list<array{seq: int, ttl: ?int, ms: float}>
     */
    private static function parseReplies(string $out): array
    {
        $replies = [];
        if (preg_match_all('/icmp_seq=(\d+)(?:.*?\bttl=(\d+))?.*?time=([\d.]+)\s*ms/', $out, $matches, PREG_SET_ORDER) !== false) {
            foreach ($matches as $match) {
                $replies[] = [
                    'seq' => (int) $match[1],
                    'ttl' => isset($match[2]) && $match[2] !== '' ? (int) $match[2] : null,
                    'ms' => round((float) $match[3], 2),
                ];
            }
        }

        return $replies;
    }

    private function tcp(NetTarget $target, string $ip): ProbeResult
    {
        $connect = $this->tcpConnect ?? static function (string $ip, int $port, int $timeoutSeconds): ?float {
            $startedAt = microtime(true);
            $socket = @stream_socket_client('tcp://'.$ip.':'.$port, $errno, $errstr, $timeoutSeconds);
            if (! is_resource($socket)) {
                return null;
            }
            fclose($socket);

            return round((microtime(true) - $startedAt) * 1000, 2);
        };

        $times = [];
        $portsTried = [];
        foreach ([443, 80] as $port) {
            for ($attempt = 0; $attempt < self::TCP_ATTEMPTS; $attempt++) {
                $portsTried[] = $port;
                $ms = ($connect)($ip, $port, 2);
                if ($ms !== null) {
                    $times[] = $ms;
                }
            }

            if ($times !== []) {
                break; // first reachable port wins
            }
        }

        $stats = self::stats($times);

        return new ProbeResult(
            probe: $this->name(),
            fetchedAt: 0,
            latencyMs: 0,
            degradedSources: ['capability:ping-binary'],
            payload: [
                'mode' => 'tcp',
                'target_ip' => $ip,
                'host' => $target->host,
                'sent' => count($portsTried),
                'received' => count($times),
                'loss_pct' => count($times) === 0 ? 100.0 : round((1 - count($times) / max(1, count($portsTried))) * 100, 1),
                'min_ms' => $stats['min'],
                'avg_ms' => $stats['avg'],
                'max_ms' => $stats['max'],
                'jitter_ms' => $stats['jitter'],
                'replies' => [],
                'tcp_port' => $times === [] ? null : $portsTried[count($portsTried) - 1],
                'unreachable' => $times === [],
            ],
        );
    }

    /**
     * @param  list<float>  $times
     * @return array{min: ?float, avg: ?float, max: ?float, jitter: ?float}
     */
    private static function stats(array $times): array
    {
        if ($times === []) {
            return ['min' => null, 'avg' => null, 'max' => null, 'jitter' => null];
        }

        $avg = array_sum($times) / count($times);
        $deviations = array_map(static fn (float $ms): float => abs($ms - $avg), $times);

        return [
            'min' => round(min($times), 2),
            'avg' => round($avg, 2),
            'max' => round(max($times), 2),
            'jitter' => round(array_sum($deviations) / count($deviations), 2),
        ];
    }

    /**
     * @param  list<string>  $argv  first element is the program name
     * @return array{exit: int, out: string}
     */
    private function run(array $argv): array
    {
        if ($this->runProcess !== null) {
            return ($this->runProcess)($argv);
        }

        $command = implode(' ', array_map(escapeshellarg(...), $argv));
        $pipes = [];

        $process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (! is_resource($process)) {
            throw new CapabilityMissingException('ping');
        }

        try {
            stream_set_timeout($pipes[1], self::DEADLINE_SECONDS + 1);
            $stdout = (string) stream_get_contents($pipes[1]);
            $stderr = (string) stream_get_contents($pipes[2]);
        } finally {
            foreach ($pipes as $pipe) {
                if (is_resource($pipe)) {
                    fclose($pipe);
                }
            }
        }

        return [
            'exit' => proc_close($process),
            'out' => $stdout."\n".$stderr,
        ];
    }
}
