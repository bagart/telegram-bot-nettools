<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

use BAGArt\TelegramBot\Contracts\Outbound\OutboundCacheContract;
use BAGArt\TelegramBotNettools\Contracts\Exceptions\QuotaExceededException;

/**
 * Quota ledger (RFC §5.3): per-user daily budget + per-chat ceiling, charged
 * through the platform's atomic incrementWithTtl pattern before probing.
 * Admin chats bypass both ledgers.
 */
final class QuotaLedger
{
    public const int WINDOW_SECONDS = 86400;

    private const string USER_KEY_PREFIX = 'tg-nettools:quota:';

    private const string CHAT_KEY_PREFIX = 'tg-nettools:quotachat:';

    /**
     * @param  array<int|string, int>  $chatOverrides  chat_id => units/day
     * @param  list<int|string>  $adminChatIds
     */
    public function __construct(
        private readonly OutboundCacheContract $cache,
        private readonly int $dailyUnits = 40,
        private readonly int $chatCeiling = 150,
        private readonly array $chatOverrides = [],
        private readonly array $adminChatIds = [],
    ) {
    }

    /** config() that degrades to $default without a Laravel container (tests). */
    private static function cfg(string $key, mixed $default): mixed
    {
        try {
            return config($key, $default);
        } catch (\Throwable) {
            return $default;
        }
    }

    public static function fromConfig(OutboundCacheContract $cache): self
    {
        return new self(
            cache: $cache,
            dailyUnits: max(1, (int) self::cfg('tg-nettools.quotas.daily_units', 40)),
            chatCeiling: max(1, (int) self::cfg('tg-nettools.quotas.chat_ceiling', 150)),
            chatOverrides: (array) self::cfg('tg-nettools.quotas.overrides', []),
            adminChatIds: (array) self::cfg('tg-nettools.admin_chat_ids', []),
        );
    }

    public function isAdminChat(int|string $chatId): bool
    {
        return in_array((string) $chatId, array_map(strval(...), $this->adminChatIds), true);
    }

    /** Effective user-level budget for this chat (override aware). */
    public function limitFor(int|string $chatId): int
    {
        return (int) ($this->chatOverrides[(string) $chatId] ?? $this->dailyUnits);
    }

    public function ceiling(): int
    {
        return $this->chatCeiling;
    }

    public function usedByUser(int|string $chatId, int|string|null $userId): int
    {
        if ($userId === null || $this->isAdminChat($chatId)) {
            return 0;
        }

        return (int) $this->cache->get($this->userKey($chatId, $userId));
    }

    public function usedInChat(int|string $chatId): int
    {
        return (int) $this->cache->get(self::CHAT_KEY_PREFIX.$chatId);
    }

    /** Remaining user budget within the binding limit (user or chat ceiling). */
    public function remaining(int|string $chatId, int|string|null $userId): int
    {
        if ($this->isAdminChat($chatId)) {
            return PHP_INT_MAX;
        }

        $remainders = [max(0, $this->limitFor($chatId) - $this->usedByUser($chatId, $userId))];
        if ($userId !== null) {
            $remainders[] = max(0, $this->chatCeiling - $this->usedInChat($chatId));
        }

        return min($remainders);
    }

    /**
     * Charge BEFORE probing; normalize/guard failures cost 0 because they
     * happen before this call.
     *
     * @throws QuotaExceededException
     */
    public function charge(int|string $chatId, int|string|null $userId, int $weight): void
    {
        if ($weight <= 0 || $this->isAdminChat($chatId)) {
            return;
        }

        if ($userId !== null) {
            $userUsed = $this->bumpAndCheck($this->userKey($chatId, $userId), $weight, $this->limitFor($chatId), true);
            if ($userUsed !== null) {
                throw new QuotaExceededException($userUsed, $this->limitFor($chatId), $this->resetsInMinutes($chatId, $userId));
            }
        }

        $chatUsed = $this->bumpAndCheck(self::CHAT_KEY_PREFIX.$chatId, $weight, $this->chatCeiling, false);
        if ($chatUsed !== null) {
            // Chat ceiling denied the run AFTER the user ledger was bumped —
            // refund it so denial consumes nothing (todo P2-4).
            if ($userId !== null) {
                $this->refund($this->userKey($chatId, $userId), $weight);
            }

            throw new QuotaExceededException($chatUsed, $this->chatCeiling, $this->resetsInMinutes($chatId, null));
        }
    }

    /** Minutes until the user's window resets (estimate from the reset marker). */
    public function resetsInMinutes(int|string $chatId, int|string|null $userId): int
    {
        $key = $userId === null
            ? self::CHAT_KEY_PREFIX.$chatId.':reset'
            : $this->userKey($chatId, $userId).':reset';

        $resetAt = $this->cache->get($key);

        if (! is_int($resetAt) && ! is_numeric($resetAt)) {
            return intdiv(self::WINDOW_SECONDS, 60);
        }

        return max(1, (int) ceil((((int) $resetAt) - time()) / 60));
    }

    /**
     * Atomic bump via incrementWithTtl; returns the new value crossed above
     * $limit, or null when allowed.
     */
    private function bumpAndCheck(string $key, int $weight, int $limit, bool $trackReset): ?int
    {
        // Over-limit short-circuit keeps denied requests from inflating the
        // counter beyond the first crossing.
        $current = (int) $this->cache->get($key);
        if ($current >= $limit) {
            return $current;
        }

        $used = $this->cache->incrementWithTtl($key, $weight, self::WINDOW_SECONDS);

        if ($trackReset && $used === $weight) {
            $this->cache->put($key.':reset', time() + self::WINDOW_SECONDS, self::WINDOW_SECONDS);
        } elseif ($trackReset && $this->cache->get($key.':reset') === null) {
            // Heal a drifted/evicted marker (adapter-dependent TTL semantics)
            $this->cache->put($key.':reset', time() + self::WINDOW_SECONDS, self::WINDOW_SECONDS);
        }

        if ($used > $limit) {
            // Roll back the crossing part so `used` sticks at the limit;
            // best-effort under the same atomic primitive.
            $this->cache->incrementWithTtl($key, $limit - $used, self::WINDOW_SECONDS);

            return $limit;
        }

        return null;
    }

    /** Compensating decrement after a denial that followed a successful user bump. */
    private function refund(string $key, int $weight): void
    {
        $this->cache->incrementWithTtl($key, -$weight, self::WINDOW_SECONDS);
    }

    private function userKey(int|string $chatId, int|string $userId): string
    {
        return self::USER_KEY_PREFIX."{$chatId}:{$userId}";
    }
}
