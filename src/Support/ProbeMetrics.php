<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

use BAGArt\TelegramBot\Contracts\Outbound\OutboundCacheContract;
use Psr\Log\LoggerInterface;

/**
 * Probe observability (RFC §11 step 1.6): one structured log line per probe
 * execution + daily ok/fail counters (cache-backed, 24h TTL). Targets are
 * logged, contact payloads never are (PII rule §5.5).
 */
final class ProbeMetrics
{
    private const string KEY_PREFIX = 'tg-nettools:m:';

    private const int TTL_SECONDS = 90000;

    public function __construct(
        private readonly OutboundCacheContract $cache,
        private readonly ?LoggerInterface $logger = null,
    ) {
    }

    /** @param list<string> $degraded */
    public function record(string $probe, bool $ok, int $latencyMs, int|string $chatId, array $degraded = [], ?string $target = null): void
    {
        $bucket = $ok && $degraded === [] ? 'ok' : ($ok ? 'degraded' : 'fail');

        $this->cache->incrementWithTtl($this->key($probe, $bucket), 1, self::TTL_SECONDS);

        $this->logger?->info('nettools.probe', [
            'probe' => $probe,
            'outcome' => $bucket,
            'latency_ms' => $latencyMs,
            'chat' => (string) $chatId,
            'target' => $target,
            'degraded' => implode(',', $degraded),
        ]);
    }

    /** Daily counter as recorded by {@see record()}. */
    public function counter(string $probe, string $bucket): int
    {
        return (int) $this->cache->get($this->key($probe, $bucket));
    }

    private function key(string $probe, string $bucket): string
    {
        return self::KEY_PREFIX.date('Ymd').":{$probe}:{$bucket}";
    }
}
