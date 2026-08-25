<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

use BAGArt\TelegramBot\Contracts\Outbound\OutboundCacheContract;

/**
 * Fixed-window per-user rate limiter for light-but-noisy commands (e.g.
 * /port: 20/hour/user, RFC §7.14). Atomic incrementWithTtl counters.
 */
final class RateLimiter
{
    private const string KEY_PREFIX = 'tg-nettools:rate:';

    public function __construct(private readonly OutboundCacheContract $cache)
    {
    }

    /**
     * Consume one slot; false = over the limit (caller sends a friendly
     * throttle card, no probe runs).
     */
    public function hit(string $scope, int|string $chatId, int|string|null $userId, int $limit, int $windowSeconds): bool
    {
        if ($userId === null || $limit <= 0) {
            return true;
        }

        $key = self::KEY_PREFIX."{$scope}:{$chatId}:{$userId}";
        $used = $this->cache->incrementWithTtl($key, 1, $windowSeconds);

        return $used <= $limit;
    }
}
