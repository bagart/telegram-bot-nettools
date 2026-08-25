<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

use BAGArt\TelegramBot\Contracts\Outbound\OutboundCacheContract;

/**
 * Per-source circuit breaker (RFC §5.4): after N consecutive failures a
 * source is skipped (degraded note, never silent) for T seconds; the next
 * window acts as half-open — one trial call, success closes, failure re-arms.
 * State lives in cache so all workers share it.
 */
final class SourceBreaker
{
    /** Sources surfaced by /nt doctor. */
    public const array KNOWN_SOURCES = ['rdap', 'whois43', 'crt.sh', 'certspotter', 'ip-api', 'ripestat', 'dns', 'check-host.net'];

    public const int FAILURE_THRESHOLD = 3;

    public const int OPEN_SECONDS = 600;

    private const string KEY_PREFIX = 'tg-nettools:brk:';

    public function __construct(private readonly OutboundCacheContract $cache)
    {
    }

    /** @return 'closed'|'open'|'half-open' */
    public function stateOf(string $source): string
    {
        $openUntil = $this->openUntil($source);
        if ($openUntil === 0) {
            return 'closed';
        }

        return time() >= $openUntil ? 'half-open' : 'open';
    }

    /**
     * May this worker call the source right now? In half-open state only the
     * first caller passes (the open window stays armed until its outcome).
     */
    public function allow(string $source): bool
    {
        return $this->stateOf($source) !== 'open';
    }

    public function recordSuccess(string $source): void
    {
        $this->cache->forget(self::KEY_PREFIX.$source.':fails');
        $this->cache->forget(self::KEY_PREFIX.$source.':open');
    }

    public function recordFailure(string $source): void
    {
        $fails = $this->cache->incrementWithTtl(self::KEY_PREFIX.$source.':fails', 1, 3600);
        if ($fails >= self::FAILURE_THRESHOLD) {
            $this->cache->put(self::KEY_PREFIX.$source.':open', time() + self::OPEN_SECONDS, 3600);
        }
    }

    /** Seconds until a half-open trial is retried (0 = not open). */
    public function retryIn(string $source): int
    {
        $openUntil = $this->openUntil($source);
        if ($openUntil === 0 || time() >= $openUntil) {
            return 0;
        }

        return max(1, $openUntil - time());
    }

    private function openUntil(string $source): int
    {
        $value = $this->cache->get(self::KEY_PREFIX.$source.':open');

        return is_numeric($value) ? (int) $value : 0;
    }
}
