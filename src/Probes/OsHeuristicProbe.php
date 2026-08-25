<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Probes;

use BAGArt\TelegramBotNettools\Contracts\NettoolsProbeContract;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;

/**
 * /os heuristic stack fingerprint (RFC §7.10): combines initial-TTL class
 * (from cached ping), HTTP Server/X-Powered-By banner and TLS ALPN hints.
 * Confidence is ALWAYS low/medium — never asserted.
 */
final class OsHeuristicProbe implements NettoolsProbeContract
{
    /** @param list<\Closure(NetTarget): ?array<string, mixed>> $signalProviders */
    public function __construct(private readonly array $signalProviders)
    {
    }

    public function name(): string
    {
        return 'os';
    }

    public function ttlSeconds(): int
    {
        return 0;
    }

    public function probe(NetTarget $target, ProbeOptions $options): ProbeResult
    {
        $signals = [];

        foreach ($this->signalProviders as $provider) {
            $signal = $provider($target);
            if ($signal !== null) {
                $signals[] = $signal;
            }
        }

        $candidates = $this->fuse($signals);

        return new ProbeResult(
            probe: $this->name(),
            fetchedAt: 0,
            latencyMs: 0,
            degradedSources: [],
            payload: [
                'host' => $target->host,
                'candidates' => $candidates,
                'insufficient' => $candidates === [],
                'signals_used' => array_map(static fn (array $s): string => (string) $s['kind'], $signals),
            ],
        );
    }

    /**
     * Deterministic fusion: each signal votes for an OS family with a fixed
     * confidence; agreeing votes upgrade confidence, disagreements stay listed.
     *
     * @param  list<array<string, mixed>>  $signals
     * @return list<array{family: string, guess: string, confidence: string, source: string}>
     */
    private function fuse(array $signals): array
    {
        $votes = [];

        foreach ($signals as $signal) {
            foreach ((array) ($signal['guesses'] ?? []) as $guess) {
                $key = mb_strtolower((string) $guess['family']);
                $entry = $votes[$key] ??= [
                    'family' => (string) $guess['family'],
                    'confidence' => 'low',
                    'sources' => [],
                    'detail' => (string) $guess['detail'],
                ];
                $entry['sources'][] = (string) $signal['kind'];
                if (count($entry['sources']) > 1) {
                    $entry['confidence'] = 'medium';
                }
            }
        }

        usort($votes, static fn (array $a, array $b): int => count($b['sources']) <=> count($a['sources']));

        return array_map(static fn (array $v): array => [
            'family' => $v['family'],
            'confidence' => $v['confidence'],
            'source' => implode('+', array_unique($v['sources'])),
            'detail' => $v['detail'],
        ], $votes);
    }

    /** Ping TTL → initial-TTL class guesses (RFC §7.10 table). */
    public static function pingSignal(array $pingPayload): ?array
    {
        $replies = (array) ($pingPayload['replies'] ?? []);
        $ttls = array_filter(array_column($replies, 'ttl'));

        if ($ttls === [] || (($pingPayload['mode'] ?? '') === 'tcp')) {
            return null;
        }

        $minTtl = min($ttls);
        [$family, $detail] = match (true) {
            $minTtl > 128 && $minTtl <= 255 => ['network gear', "initial TTL ≈ 255 ($minTtl observed)"],
            $minTtl > 64 && $minTtl <= 128 => ['Windows', "initial TTL ≈ 128 ($minTtl observed)"],
            default => ['Linux/BSD', "initial TTL ≈ 64 ($minTtl observed)"],
        };

        return [
            'kind' => 'ttl',
            'guesses' => [['family' => $family, 'detail' => $detail]],
        ];
    }

    /** HTTP banner → OS family guesses (self-declared only). */
    public static function httpBannerSignal(?string $server, ?string $poweredBy): ?array
    {
        $banner = trim(($server ?? '').' '.($poweredBy ?? ''));
        if ($banner === '') {
            return null;
        }

        $guesses = [];
        if (stripos($banner, 'win') !== false || stripos($banner, 'iis') !== false) {
            $guesses[] = ['family' => 'Windows', 'detail' => "banner: {$banner}"];
        }
        if (preg_match('/ubuntu|debian|centos|fedora|red\s?hat|nginx|apache|php/i', $banner)) {
            $guesses[] = ['family' => 'Linux/BSD', 'detail' => "banner: {$banner}"];
        }
        if (stripos($banner, 'cloudflare') !== false || stripos($banner, 'envoy') !== false) {
            $guesses[] = ['family' => 'edge/proxy (OS hidden)', 'detail' => "banner: {$banner}"];
        }

        return $guesses === [] ? null : ['kind' => 'http-banner', 'guesses' => $guesses];
    }

    /** TLS ALPN hint — h2 usually means a modern userspace, weak signal only. */
    public static function tlsAlpnSignal(array $alpn): ?array
    {
        if ($alpn === []) {
            return null;
        }

        return [
            'kind' => 'tls-alpn',
            'guesses' => [[
                'family' => in_array('h2', $alpn, true) ? 'modern server (Linux likely)' : 'generic',
                'detail' => 'ALPN: '.implode(', ', $alpn),
            ]],
        ];
    }
}
