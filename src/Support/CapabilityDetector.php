<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

use BAGArt\AsyncKernel\Contracts\Daemons\ASKWarmableContract;
use BAGArt\TelegramBot\Contracts\Outbound\OutboundCacheContract;
use Closure;

/**
 * Binary capability detection at warm()-time (RFC §10.4): missing
 * capabilities degrade commands at registry time, not at call time.
 */
final class CapabilityDetector implements ASKWarmableContract
{
    private const string CACHE_PREFIX = 'tg-nettools:cap:';

    /** @var list<string> */
    public const array DETECTED_BINARIES = ['ping', 'traceroute', 'tracepath'];

    /**
     * @param  (Closure(string): bool)|null  $binaryExists  test seam; default
     *                                                      `command -v` probe
     */
    public function __construct(
        private readonly OutboundCacheContract $cache,
        private readonly ?Closure $binaryExists = null,
    ) {
    }

    public function warm(): void
    {
        foreach (self::DETECTED_BINARIES as $binary) {
            $this->hasBinary($binary);
        }
    }

    public function hasBinary(string $binary): bool
    {
        $key = self::CACHE_PREFIX.$binary;
        $cached = $this->cache->get($key);
        if (is_bool($cached)) {
            return $cached;
        }

        $exists = ($this->binaryExists ?? self::defaultBinaryExists())($binary);
        $this->cache->put($key, $exists, 86400 * 365);

        return $exists;
    }

    /** traceroute binary if any flavor exists, else null → /trace degrades. */
    public function traceBinary(): ?string
    {
        foreach (['traceroute', 'tracepath'] as $binary) {
            if ($this->hasBinary($binary)) {
                return $binary;
            }
        }

        return null;
    }

    public function pingAvailable(): bool
    {
        return $this->hasBinary('ping');
    }

    /** @return list<string> status lines for the /nt card */
    public function summaryLines(): array
    {
        $trace = $this->traceBinary();

        return [
            'ping: '.$this->mark($this->pingAvailable()),
            'trace: '.($trace !== null ? $trace.' ✅' : $this->mark(false)),
        ];
    }

    private function mark(bool $present): string
    {
        return $present ? '✅' : '⚠️ missing';
    }

    private static function defaultBinaryExists(): Closure
    {
        return static function (string $binary): bool {
            $output = [];
            $exitCode = 1;

            exec('command -v '.escapeshellarg($binary).' 2>/dev/null', $output, $exitCode);

            return $exitCode === 0 && $output !== [];
        };
    }
}
