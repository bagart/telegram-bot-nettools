<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Probes;

use BAGArt\TelegramBotNettools\Contracts\NettoolsProbeContract;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;

/**
 * /port probe (RFC §7.14): single TCP connect to one guard-approved IP:port
 * (300 ms), banner grab ≤256 B on success (protocol guessed by port; SNI set
 * for 443). "closed" (RST) vs "filtered" (silence/unreachable) wording is
 * deliberate. Measurements are never cached.
 */
final class PortProbe implements NettoolsProbeContract
{
    public const int CONNECT_TIMEOUT_SECONDS = 1;

    private const int BANNER_BYTES = 256;

    /** @var (Closure(string $ip, int $port, string|null $sniHost): array{connected: bool, errno: int, banner: string, latency_ms: float})|null */
    private readonly ?\Closure $connector;

    public function __construct(
        private readonly int $port,
        ?\Closure $connector = null,
    ) {
        if ($port < 1 || $port > 65535) {
            throw new \InvalidArgumentException("invalid port: {$port}");
        }

        $this->connector = $connector;
    }

    public function name(): string
    {
        return 'port';
    }

    public function ttlSeconds(): int
    {
        return 0;
    }

    public function probe(NetTarget $target, ProbeOptions $options): ProbeResult
    {
        $ip = $target->ips[0];
        $sniHost = ! $target->isIp && $this->port === 443 ? $target->host : null;

        $connect = $this->connector ?? self::defaultConnector();
        ['connected' => $connected, 'errno' => $errno, 'banner' => $banner, 'latency_ms' => $latencyMs]
            = ($connect)($ip, $this->port, $sniHost);

        [$state, $hint] = self::classify($connected, $errno);

        return new ProbeResult(
            probe: $this->name(),
            fetchedAt: 0,
            latencyMs: 0,
            degradedSources: [],
            payload: [
                'host' => $target->host,
                'ip' => $ip,
                'port' => $this->port,
                'state' => $state,
                'hint' => $hint,
                'latency_ms' => $connected ? round($latencyMs, 2) : null,
                'banner' => $banner === '' ? null : mb_substr($banner, 0, self::BANNER_BYTES),
                'protocol' => self::guessProtocol($this->port),
            ],
        );
    }

    /**
     * @return array{0: string, 1: ?string} state + optional user hint
     */
    private static function classify(bool $connected, int $errno): array
    {
        if ($connected) {
            return ['open', null];
        }

        // ECONNREFUSED (111 / macOS 61 / Windows 10061) — the host answered:
        // nothing listens on that port
        if (in_array($errno, [111, 61, 10061], true)) {
            return ['closed', 'host responded: nothing listening on this port'];
        }

        return ['filtered', null];
    }

    private static function guessProtocol(int $port): ?string
    {
        return match (true) {
            in_array($port, [80, 8080, 8000, 8888], true) => 'http',
            $port === 443 || $port === 8443 => 'https',
            in_array($port, [25, 587, 465], true) => 'smtp',
            $port === 22 => 'ssh',
            $port === 21 => 'ftp',
            default => null,
        };
    }

    /** @return Closure(string, int, string|null): array{connected: bool, errno: int, banner: string, latency_ms: float} */
    private static function defaultConnector(): \Closure
    {
        return static function (string $ip, int $port, ?string $sniHost): array {
            $transport = $port === 443 ? 'ssl' : 'tcp';
            $context = stream_context_create($sniHost !== null ? ['ssl' => ['SNI_enabled' => true, 'peer_name' => $sniHost]] : []);

            $startedAt = microtime(true);
            $socket = @stream_socket_client(
                "{$transport}://{$ip}:{$port}",
                $errno,
                $errstr,
                PortProbe::CONNECT_TIMEOUT_SECONDS,
                STREAM_CLIENT_CONNECT,
                $context,
            );
            $latencyMs = (microtime(true) - $startedAt) * 1000;

            if (! is_resource($socket)) {
                return ['connected' => false, 'errno' => $errno, 'banner' => '', 'latency_ms' => $latencyMs];
            }

            try {
                stream_set_timeout($socket, 2);

                if (in_array($port, [80, 8080, 8000, 8888], true)) {
                    @fwrite($socket, "HEAD / HTTP/1.0\r\nHost: nettools\r\n\r\n");
                } elseif (in_array($port, [25, 587, 465], true)) {
                    // SMTP greets first — just read
                }

                $banner = '';
                while (strlen($banner) < PortProbe::BANNER_BYTES) {
                    $chunk = @fread($socket, PortProbe::BANNER_BYTES - strlen($banner));
                    if ($chunk === false || $chunk === '') {
                        break;
                    }
                    $banner .= $chunk;
                }

                return [
                    'connected' => true,
                    'errno' => 0,
                    'banner' => trim((string) preg_replace('/[^\x20-\x7e]+/', ' ', $banner)),
                    'latency_ms' => $latencyMs,
                ];
            } finally {
                fclose($socket);
            }
        };
    }
}
