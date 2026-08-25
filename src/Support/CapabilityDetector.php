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

    /** Short TTL: binaries change with deploys, and the key is only valid for this host (todo P2-3). */
    private const int CACHE_TTL_SECONDS = 300;

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
        $cached = $this->cache->get($this->cacheKeyFor($binary));
        if (is_bool($cached)) {
            return $cached;
        }

        $exists = ($this->binaryExists ?? self::defaultBinaryExists())($binary);
        $this->cache->put($this->cacheKeyFor($binary), $exists, self::CACHE_TTL_SECONDS);

        return $exists;
    }

    /**
     * Shared cache keys are scoped to the current host fingerprint
     * (hostname + machine class): worker B on a different box must never
     * trust worker A's detection result.
     */
    public static function cacheKeyFor(string $binary): string
    {
        return self::CACHE_PREFIX.self::hostFingerprint().':'.$binary;
    }

    private static function hostFingerprint(): string
    {
        return substr(sha1((gethostname() ?: 'unknown').'|'.php_uname('m')), 0, 8);
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
