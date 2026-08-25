<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

use BAGArt\TelegramBot\Contracts\Outbound\OutboundCacheContract;

/**
 * Two-step interaction state (`nt-form:{chat}:{user}`, TTL 120s): remembers a
 * pending action (e.g. "trace awaiting target") between the prompt and the
 * follow-up message. State only — the completing processor re-validates.
 */
final class FormState
{
    private const string KEY_PREFIX = 'tg-nettools:form:';

    private const int TTL_SECONDS = 120;

    public function __construct(private readonly OutboundCacheContract $cache)
    {
    }

    /**
     * @param  array<string, mixed>  $state
     */
    public function set(int|string $chatId, int|string|null $userId, array $state): void
    {
        if ($userId === null) {
            return; // forms are strictly per-user — anonymous chats skip
        }

        $this->cache->put(
            self::KEY_PREFIX."{$chatId}:{$userId}",
            json_encode($state, JSON_THROW_ON_ERROR),
            self::TTL_SECONDS,
        );
    }

    /** @return array{action: string, extra?: string}|null */
    public function get(int|string $chatId, int|string|null $userId): ?array
    {
        if ($userId === null) {
            return null;
        }

        $raw = $this->cache->get(self::KEY_PREFIX."{$chatId}:{$userId}");
        if (! is_string($raw)) {
            return null;
        }

        try {
            /** @var array<string, mixed> $decoded */
            $decoded = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }

        return is_string($decoded['action'] ?? null) ? $decoded : null;
    }

    public function clear(int|string $chatId, int|string|null $userId): void
    {
        if ($userId === null) {
            return;
        }

        $this->cache->forget(self::KEY_PREFIX."{$chatId}:{$userId}");
    }
}
