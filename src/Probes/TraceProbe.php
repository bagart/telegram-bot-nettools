<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Probes;

use BAGArt\TelegramBotNettools\Contracts\MmdbContract;
use BAGArt\TelegramBotNettools\Contracts\NettoolsProbeContract;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Support\CapabilityDetector;

/**
 * /trace probe (RFC §7.5): traceroute (or tracepath) binary, resolved-IP
 * argv-safe; hops with RTTs, per-hop ASN via mmdb, destination-reached marker.
 * Firewalled hops stay honest `* * *` rows. Measurements are never cached.
 *
 * With an `onHop` hook the live proc path streams each parsed hop out as it
 * arrives (progressive preview); without it the run stays a bulk read.
 */
final class TraceProbe implements NettoolsProbeContract
{
    private const int DEADLINE_SECONDS = 15;

    /** @var (Closure(list<string> $argv): array{exit: int, out: string})|null */
    private readonly ?\Closure $runProcess;

    /**
     * Test seam mirroring the live proc path: receives an emit(string $line)
     * callback that must be invoked once per raw stdout line, in order.
     *
     * @var (Closure(list<string> $argv, callable $emit): array{exit: int, out: string})|null
     */
    private readonly ?\Closure $runStreaming;

    /**
     * Progressive-preview hook: invoked once per parsed hop as it arrives,
     * with array{n, ip, ms, timeout} (ASN is enriched only on the final card).
     *
     * @var (Closure(array{n: int, ip: ?string, ms: list<float>, timeout: bool}): void)|null
     */
    private readonly ?\Closure $onHop;

    public function __construct(
        private readonly CapabilityDetector $capabilities,
        private readonly ?MmdbContract $mmdb = null,
        ?\Closure $runProcess = null,
        private readonly int $maxHops = 15,
        ?\Closure $onHop = null,
        ?\Closure $runStreaming = null,
    ) {
        $this->runProcess = $runProcess;
        $this->onHop = $onHop;
        $this->runStreaming = $runStreaming;
    }

    public function name(): string
    {
        return 'trace';
    }

    public function ttlSeconds(): int
    {
        return 0;
    }

    public function probe(NetTarget $target, ProbeOptions $options): ProbeResult
    {
        $binary = $this->capabilities->traceBinary();
        if ($binary === null) {
            throw new \LogicException('no traceroute/tracepath binary on this host');
        }

        $ip = $target->ips[0];
        ['exit' => $exit, 'out' => $out] = $this->run($binary, $ip);

        // Old tracepath builds reject -m; plain retry keeps the command alive
        if ($exit !== 0 && trim($out) === '' && $binary === 'tracepath') {
            ['exit' => $exit, 'out' => $out] = $this->runPlain($binary, $ip);
        }

        $hops = self::parseHops($out, $this->maxHops);
        foreach ($hops as $index => $hop) {
            $hops[$index]['asn'] = ($hop['ip'] !== null && $this->mmdb !== null)
                ? ($this->mmdb->asn($hop['ip'])['asn'] ?? null)
                : null;
        }

        return new ProbeResult(
            probe: $this->name(),
            fetchedAt: 0,
            latencyMs: 0,
            degradedSources: [],
            payload: [
                'binary' => $binary,
                'target_ip' => $ip,
                'host' => $target->host,
                'hops' => $hops,
                'hop_count' => count($hops),
                'max_hops' => $this->maxHops,
                'truncated' => count($hops) >= $this->maxHops && ! self::reached($hops, $ip),
                'reached' => self::reached($hops, $ip),
                'binary_exit' => $exit,
            ],
        );
    }

    /**
     * @return list<array{n: int, ip: ?string, asn: int|null, ms: list<float>, timeout: bool}>
     */
    private static function parseHops(string $out, int $maxHops): array
    {
        $hops = [];

        foreach (explode("\n", $out) as $line) {
            if (($hop = self::hopFromLine($line, $maxHops)) === null || isset($hops[$hop['n'] - 1])) {
                continue;
            }
            $hops[$hop['n'] - 1] = $hop;
        }

        ksort($hops);

        return array_values($hops);
    }

    /**
     * One traceroute/tracepath output line → hop row; headers ("traceroute
     * to ...") and out-of-range hop numbers yield null.
     *
     * @return array{n: int, ip: ?string, asn: null, ms: list<float>, timeout: bool}|null
     */
    private static function hopFromLine(string $line, int $maxHops): ?array
    {
        if (preg_match('/^\s*(\d{1,3})[.:)]?\s+(.*)$/', $line, $m) !== 1) {
            return null;
        }

        $n = (int) $m[1];
        if ($n < 1 || $n > $maxHops) {
            return null;
        }

        $body = $m[2];

        // First globally-routable-looking address on the line wins
        $ip = null;
        if (preg_match('/(?:^|[\s(\[])((?:\d{1,3}\.){3}\d{1,3})(?:[\s)\].]|$)/', $body, $ipMatch) === 1) {
            $ip = $ipMatch[1];
        } elseif (preg_match('/((?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4})/i', $body, $ipMatch6) === 1) {
            $ip = strtolower($ipMatch6[1]);
        }

        $ms = [];
        if (preg_match_all('/([\d.]+)\s*ms/', $body, $rtts) === 1 && $rtts[1] !== []) {
            $ms = array_map(floatval(...), $rtts[1]);
        }

        return [
            'n' => $n,
            'ip' => $ip,
            'asn' => null,
            'ms' => $ms,
            'timeout' => $ms === [],
        ];
    }

    /**
     * @param  list<array{n: int, ip: ?string, asn: int|null, ms: list<float>, timeout: bool}>  $hops
     */
    private static function reached(array $hops, string $ip): bool
    {
        $last = end($hops);

        return $last !== false && mb_strtolower((string) ($last['ip'] ?? '')) === mb_strtolower($ip);
    }

    /**
     * @return array{exit: int, out: string}
     */
    private function run(string $binary, string $ip): array
    {
        $flags = match ($binary) {
            'traceroute' => ['-n', '-q', '1', '-m', (string) $this->maxHops, '-w', '2'],
            default => ['-m', (string) ($this->maxHops + 1), '-n'], // tracepath
        };

        return $this->execute([$binary, ...$flags, '--', $ip]);
    }

    /**
     * Fallback without -m/-- flags for tracepath builds that reject them.
     *
     * @return array{exit: int, out: string}
     */
    private function runPlain(string $binary, string $ip): array
    {
        return $this->execute([$binary, '-n', $ip]);
    }

    /**
     * Live stdout pump: parses each raw line into a hop and forwards fresh
     * ones to the preview hook. Returns null when no hook is attached.
     *
     * @return \Closure(string): void|null
     */
    private function emitter(): ?\Closure
    {
        if ($this->onHop === null) {
            return null;
        }

        $seen = [];

        return function (string $line) use (&$seen): void {
            if (($hop = self::hopFromLine(rtrim($line, "\r\n"), $this->maxHops)) === null || isset($seen[$hop['n']])) {
                return;
            }
            $seen[$hop['n']] = true;
            ($this->onHop)(['n' => $hop['n'], 'ip' => $hop['ip'], 'ms' => $hop['ms'], 'timeout' => $hop['timeout']]);
        };
    }

    /** Replay a bulk buffer through the same emitter (fake-runner path). */
    private function replayHops(string $out): void
    {
        $emit = $this->emitter();
        if ($emit === null) {
            return;
        }
        foreach (explode("\n", $out) as $line) {
            $emit($line);
        }
    }

    /**
     * @param  list<string>  $argv  first element is the program name
     * @return array{exit: int, out: string}
     */
    private function execute(array $argv): array
    {
        if ($this->runProcess !== null) {
            $outcome = ($this->runProcess)($argv);
            $this->replayHops((string) $outcome['out']);

            return $outcome;
        }

        if ($this->runStreaming !== null) {
            $emit = $this->emitter() ?? static function (string $line): void {
            };

            return ($this->runStreaming)($argv, $emit);
        }

        $command = implode(' ', array_map(escapeshellarg(...), $argv));
        $pipes = [];

        $process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (! is_resource($process)) {
            throw new \RuntimeException('proc_open unavailable');
        }

        try {
            stream_set_timeout($pipes[1], self::DEADLINE_SECONDS + 5);

            if (($emit = $this->emitter()) === null) {
                $stdout = (string) stream_get_contents($pipes[1]);
            } else {
                // Line-by-line read so previews go out while hops arrive
                $stdout = '';
                while (($line = fgets($pipes[1])) !== false) {
                    $stdout .= $line;
                    $emit($line);
                }
            }
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
