<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

use BAGArt\TelegramBot\Contracts\Outbound\OutboundCacheContract;
use BAGArt\TelegramBotNettools\NettoolsSettings;

/**
 * Per-chat settings overlay (RFC §3.5, OQ4 MVP decision): long-TTL cache
 * keyed by chat; null values inherit the global NettoolsSettings defaults.
 */
final class ChatSettings
{
    private const string KEY_PREFIX = 'tg-nettools:set:';

    private const int TTL = 86400 * 30;

    public function __construct(private readonly OutboundCacheContract $cache)
    {
    }

    public static function of(OutboundCacheContract $cache): self
    {
        return new self($cache);
    }

    /** @return array{detail_mode:string, heavy_confirm:?bool, auto_capture:?bool} */
    private function load(int|string $chatId): array
    {
        $raw = $this->cache->get(self::KEY_PREFIX.$chatId);
        $state = is_array($raw) ? $raw : [];

        return [
            'detail_mode' => is_string($state['detail_mode'] ?? null) ? $state['detail_mode'] : 'compact',
            'heavy_confirm' => is_bool($state['heavy_confirm'] ?? null) ? $state['heavy_confirm'] : null,
            'auto_capture' => is_bool($state['auto_capture'] ?? null) ? $state['auto_capture'] : null,
        ];
    }

    /** Global settings with the chat overlay applied. */
    public function apply(int|string $chatId, NettoolsSettings $settings): NettoolsSettings
    {
        $overlay = $this->load($chatId);

        return new NettoolsSettings(
            reconEnabled: $settings->reconEnabled,
            activeEnabled: $settings->activeEnabled,
            auditEnabled: $settings->auditEnabled,
            portscanEnabled: $settings->portscanEnabled,
            dnsblEnabled: $settings->dnsblEnabled,
            timeoutRdap: $settings->timeoutRdap,
            timeoutWhois43: $settings->timeoutWhois43,
            timeoutDns: $settings->timeoutDns,
            timeoutHttpFetch: $settings->timeoutHttpFetch,
            timeoutPing: $settings->timeoutPing,
            pingPackets: $settings->pingPackets,
            traceHops: $settings->traceHops,
            portRatePerHour: $settings->portRatePerHour,
            heavyConfirm: $overlay['heavy_confirm'] ?? $settings->heavyConfirm,
            memoryEnabled: $settings->memoryEnabled,
            autoCapture: $overlay['auto_capture'] ?? $settings->autoCapture,
            maxTargets: $settings->maxTargets,
        );
    }

    /** @return array{detail_mode:string, heavy_confirm:?bool, auto_capture:?bool} */
    public function raw(int|string $chatId): array
    {
        return $this->load($chatId);
    }

    public function setHeavyConfirm(int|string $chatId, bool $value): void
    {
        $this->merge($chatId, ['heavy_confirm' => $value]);
    }

    public function setAutoCapture(int|string $chatId, bool $value): void
    {
        $this->merge($chatId, ['auto_capture' => $value]);
    }

    public function setDetailMode(int|string $chatId, string $mode): void
    {
        $this->merge($chatId, ['detail_mode' => $mode === 'full' ? 'full' : 'compact']);
    }

    /** @param array<string, mixed> $patch */
    private function merge(int|string $chatId, array $patch): void
    {
        $this->cache->put(self::KEY_PREFIX.$chatId, [...$this->load($chatId), ...$patch], self::TTL);
    }
}
