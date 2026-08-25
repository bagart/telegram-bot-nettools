<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

use BAGArt\AsyncKernel\Contracts\ASKLockerContract;
use BAGArt\TelegramBot\Contracts\Outbound\OutboundCacheContract;
use BAGArt\TelegramBotNettools\Contracts\Exceptions\NxDomainException;
use BAGArt\TelegramBotNettools\Contracts\NettoolsProbeContract;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;

/**
 * Layered probe cache (RFC §6): key = sha256(normalized host + options),
 * stampede protection via platform lock (single composer, others wait then
 * read), negative caching for NXDOMAIN, never-cache for measurements.
 */
final class ProbeCache
{
    private const string KEY_PREFIX = 'tg-nettools:';

    private const string NEGATIVE_PREFIX = 'tg-nettools:nx:';

    private const string LOCK_PREFIX = 'tg-nettools:sflight:';

    private const int NEGATIVE_TTL_SECONDS = 300;

    private const int STAMPEDE_LOCK_TTL_SECONDS = 30;

    private const int STAMPEDE_WAIT_MS = 2000;

    private const int STAMPEDE_POLL_MS = 50;

    public function __construct(
        private readonly OutboundCacheContract $cache,
        private readonly ASKLockerContract $locker,
    ) {
    }

    public static function cacheKey(NettoolsProbeContract|string $probe, NetTarget $target, ProbeOptions $options): string
    {
        return self::KEY_PREFIX.self::nameOf($probe).':'.self::hashOf($target, $options);
    }

    /**
     * @param  callable(): ProbeResult  $composer  fresh-probe factory; runs at
     *                                             most once per key under lock
     */
    public function getOrSet(
        NettoolsProbeContract $probe,
        NetTarget $target,
        ProbeOptions $options,
        callable $composer,
    ): ProbeResult {
        if ($probe->ttlSeconds() <= 0 || $options->flag(ProbeOptions::FLAG_SKIP_CACHE)) {
            return $this->measure($composer);
        }

        $key = self::KEY_PREFIX.$probe->name().':'.self::hashOf($target, $options);
        $negativeKey = self::NEGATIVE_PREFIX.$probe->name().':'.self::hashOf($target, $options);

        if (! $options->flag(ProbeOptions::FLAG_BYPASS_NEGATIVE_CACHE)) {
            $tombstone = $this->cache->get($negativeKey);
            if ($tombstone !== null) {
                throw new NxDomainException($target->host, "cached NXDOMAIN for {$target->host}");
            }
        }

        $cached = $this->readResult($key);
        if ($cached !== null) {
            return $cached;
        }

        $lockOwner = bin2hex(random_bytes(8));
        $lockAcquired = $this->locker->acquireWithTtl(
            self::LOCK_PREFIX.$key,
            self::STAMPEDE_LOCK_TTL_SECONDS,
            $lockOwner,
        );

        if (! $lockAcquired) {
            // Another worker composes: wait briefly, then read its result
            $deadlineMs = microtime(true) * 1000 + self::STAMPEDE_WAIT_MS;
            do {
                usleep(self::STAMPEDE_POLL_MS * 1000);
                $shared = $this->readResult($key);
                if ($shared !== null) {
                    return $shared;
                }
            } while (microtime(true) * 1000 < $deadlineMs);

            // Degrade: compose without the lock rather than fail the user
            return $this->composeAndStore($key, $negativeKey, $probe->ttlSeconds(), $composer);
        }

        try {
            $doubleChecked = $this->readResult($key);
            if ($doubleChecked !== null) {
                return $doubleChecked;
            }

            return $this->composeAndStore($key, $negativeKey, $probe->ttlSeconds(), $composer);
        } finally {
            $this->locker->releaseWithOwner(self::LOCK_PREFIX.$key, $lockOwner);
        }
    }

    public function forget(string $probeName, NetTarget $target, ProbeOptions $options): void
    {
        $hash = self::hashOf($target, $options);
        $this->cache->forget(self::KEY_PREFIX."{$probeName}:{$hash}");
        $this->cache->forget(self::NEGATIVE_PREFIX."{$probeName}:{$hash}");
    }

    private static function nameOf(NettoolsProbeContract|string $probe): string
    {
        return is_string($probe) ? $probe : $probe->name();
    }

    private static function hashOf(NetTarget $target, ProbeOptions $options): string
    {
        return hash('sha256', $target->host.'|'.$options->cacheHash());
    }

    /**
     * @param  callable(): ProbeResult  $composer
     */
    private function composeAndStore(string $key, string $negativeKey, int $ttl, callable $composer): ProbeResult
    {
        try {
            $result = $this->measure($composer);
        } catch (NxDomainException $exception) {
            $this->cache->put($negativeKey, 1, self::NEGATIVE_TTL_SECONDS);

            throw $exception;
        }

        $this->cache->put($key, json_encode($result->toArray(), JSON_THROW_ON_ERROR), $ttl);

        return $result;
    }

    /**
     * @param  callable(): ProbeResult  $composer
     */
    private function measure(callable $composer): ProbeResult
    {
        $startedAt = microtime(true);
        $result = $composer();

        return $result->withTiming(time(), (int) round((microtime(true) - $startedAt) * 1000));
    }

    private function readResult(string $key): ?ProbeResult
    {
        $raw = $this->cache->get($key);
        if (! is_string($raw) || $raw === '') {
            return null;
        }

        try {
            /** @var array<string, mixed> $decoded */
            $decoded = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);

            return ProbeResult::fromArray($decoded);
        } catch (\JsonException|\InvalidArgumentException) {
            $this->cache->forget($key);

            return null;
        }
    }
}
