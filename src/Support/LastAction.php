<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

use BAGArt\TelegramBot\Contracts\Outbound\OutboundCacheContract;

/**
 * Last executed nettools command per chat (`/r` repeat-last, RFC §3.1):
 * stores {command, args} for 48h; /r re-runs it and the target command
 * charges its own weight.
 */
final class LastAction
{
    private const string KEY_PREFIX = 'tg-nettools:last:';

    private const int TTL_SECONDS = 172800;

    public function __construct(private readonly OutboundCacheContract $cache)
    {
    }

    public function record(int|string $chatId, string $command, string $args): void
    {
        $this->cache->put(
            self::KEY_PREFIX.$chatId,
            json_encode(['command' => $command, 'args' => $args], JSON_THROW_ON_ERROR),
            self::TTL_SECONDS,
        );
    }

    /** @return array{command: string, args: string}|null */
    public function recall(int|string $chatId): ?array
    {
        $raw = $this->cache->get(self::KEY_PREFIX.$chatId);
        if (! is_string($raw)) {
            return null;
        }

        try {
            /** @var array<string, mixed> $decoded */
            $decoded = json_decode($raw, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }

        if (! is_string($decoded['command'] ?? null)) {
            return null;
        }

        return ['command' => $decoded['command'], 'args' => (string) ($decoded['args'] ?? '')];
    }
}
