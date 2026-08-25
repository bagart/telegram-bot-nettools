<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

use BAGArt\TelegramBot\Contracts\Outbound\OutboundCacheContract;

/**
 * Short-hash target refs for callback_data (RFC §3.6): `h{10hex}` →
 * {host, command} pair, TTL 24h. Callbacks never carry raw hosts.
 */
final class TargetRef
{
    private const string KEY_PREFIX = 'tg-nettools:ref:';

    private const int TTL = 86400;

    public function __construct(private readonly OutboundCacheContract $cache)
    {
    }

    public function remember(string $host, string $command = ''): string
    {
        $hash = 'h'.substr(hash('sha256', $host.'|'.$command), 0, 10);

        $this->cache->put(
            self::KEY_PREFIX.$hash,
            ['host' => $host, 'command' => $command],
            self::TTL,
        );

        return $hash;
    }

    /** @return array{host: string, command: string}|null */
    public function resolve(string $hash): ?array
    {
        $entry = $this->cache->get(self::KEY_PREFIX.$hash);

        return is_array($entry) && isset($entry['host'])
            ? ['host' => (string) $entry['host'], 'command' => (string) ($entry['command'] ?? '')]
            : null;
    }
}
