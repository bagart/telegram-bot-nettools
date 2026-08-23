<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Results;

/**
 * Per-probe call options. Part of the cache key (see ProbeOptions::cacheHash()).
 */
final readonly class ProbeOptions
{
    public const string FLAG_SKIP_CACHE = 'skip_cache';
    public const string FLAG_BYPASS_NEGATIVE_CACHE = 'bypass_negative_cache';

    /**
     * @param  array<string, bool|int|string|null>  $flags
     */
    public function __construct(
        public array $flags = [],
        public int $timeoutSeconds = 5,
    ) {
    }

    public function flag(string $name, bool $default = false): bool
    {
        $value = $this->flags[$name] ?? null;

        return is_bool($value) ? $value : $default;
    }

    public function withFlag(string $name, bool|int|string|null $value = true): self
    {
        return new self([...$this->flags, $name => $value], $this->timeoutSeconds);
    }

    /** Stable contribution to the probe-cache key (sorted → order-insensitive). */
    public function cacheHash(): string
    {
        $flags = $this->flags;
        ksort($flags);

        return md5(json_encode([$flags, $this->timeoutSeconds], JSON_THROW_ON_ERROR));
    }
}
