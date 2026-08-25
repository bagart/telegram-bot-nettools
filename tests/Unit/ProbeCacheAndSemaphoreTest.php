<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Unit;

use BAGArt\TelegramBot\Contracts\Outbound\OutboundCacheContract;
use BAGArt\TelegramBotNettools\Contracts\Exceptions\NxDomainException;
use BAGArt\TelegramBotNettools\Contracts\Exceptions\SemaphoreBusyException;
use BAGArt\TelegramBotNettools\Results\GuardVerdict;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Support\ProbeCache;
use BAGArt\TelegramBotNettools\Support\ProbeSemaphore;
use BAGArt\TelegramBotNettools\Tests\Support\FakeLocker;
use BAGArt\TelegramBotNettools\Tests\Support\FakeOutboundCacheFactory;
use BAGArt\TelegramBotNettools\Tests\Support\FixtureProbe;
use PHPUnit\Framework\TestCase;

/**
 * ProbeCache + ProbeSemaphore on in-memory platform primitives.
 */
final class ProbeCacheAndSemaphoreTest extends TestCase
{
    public function test_composes_once_then_serves_cached(): void
    {
        [$cache, $locker] = $this->primitives();
        $probeCache = new ProbeCache($cache, $locker);
        $runs = 0;

        $probe = new FixtureProbe(600);
        $target = self::target('example.com');

        $first = $probeCache->getOrSet($probe, $target, new ProbeOptions(), function () use (&$runs): ProbeResult {
            $runs++;

            return new ProbeResult('fixture', 0, 0, [], ['v' => 'fresh']);
        });
        $second = $probeCache->getOrSet($probe, $target, new ProbeOptions(), function () use (&$runs): ProbeResult {
            $runs++;

            return new ProbeResult('fixture', 0, 0, [], ['v' => 'never']);
        });

        self::assertSame(1, $runs);
        self::assertSame('fresh', $second->payload['v']);
        self::assertSame($first->toArray(), $second->toArray());
        // measured timing filled in
        self::assertGreaterThan(0, $first->fetchedAt);
    }

    public function test_ttl_zero_never_caches(): void
    {
        [$cache, $locker] = $this->primitives();
        $probeCache = new ProbeCache($cache, $locker);
        $runs = 0;

        $probe = new FixtureProbe(0);

        foreach ([1, 2] as $_) {
            $probeCache->getOrSet($probe, self::target('example.com'), new ProbeOptions(), function () use (&$runs): ProbeResult {
                $runs++;

                return new ProbeResult('fixture', 0, 0);
            });
        }

        self::assertSame(2, $runs);
    }

    public function test_nxdomain_negative_cache_and_bypass(): void
    {
        [$cache, $locker] = $this->primitives();
        $probeCache = new ProbeCache($cache, $locker);
        $runs = 0;

        $composer = function () use (&$runs): ProbeResult {
            $runs++;
            throw new NxDomainException('missing.example');
        };
        $probe = new FixtureProbe(600);
        $options = new ProbeOptions();

        try {
            $probeCache->getOrSet($probe, self::target('missing.example'), $options, $composer);
            self::fail('expected NxDomainException');
        } catch (NxDomainException) {
        }

        try {
            $probeCache->getOrSet($probe, self::target('missing.example'), $options, $composer);
            self::fail('expected cached NxDomainException without composing');
        } catch (NxDomainException) {
        }
        self::assertSame(1, $runs);

        try {
            $probeCache->getOrSet(
                $probe,
                self::target('missing.example'),
                (new ProbeOptions())->withFlag(ProbeOptions::FLAG_BYPASS_NEGATIVE_CACHE),
                $composer,
            );
            self::fail('expected NxDomainException after bypass');
        } catch (NxDomainException) {
        }
        self::assertSame(2, $runs);
    }

    public function test_stampede_waits_for_foreign_composer_result(): void
    {
        [, $locker] = $this->primitives();
        $cache = FakeOutboundCacheFactory::create();
        $fakeLocker = new FakeLocker();
        $probeCache = new ProbeCache($cache, $fakeLocker);

        $probe = new FixtureProbe(600);
        $target = self::target('example.com');

        $key = ProbeCache::cacheKey($probe, $target, new ProbeOptions());
        $lockKey = 'tg-nettools:sflight:'.$key;

        // Another worker holds the single-flight lock and already stored the result
        $fakeLocker->forceLock($lockKey, 'other-worker');
        $shared = new ProbeResult('fixture', time(), 42, [], ['v' => 'shared']);
        $cache->put($key, json_encode($shared->toArray(), JSON_THROW_ON_ERROR), 600);

        $result = $probeCache->getOrSet($probe, $target, new ProbeOptions(), fn (): ProbeResult => throw new \LogicException('must not compose under foreign lock'));

        self::assertSame('shared', $result->payload['v']);
        self::assertSame(42, $result->latencyMs);
    }

    public function test_corrupt_entry_is_recomposed(): void
    {
        [$cache, $locker] = $this->primitives();
        $probeCache = new ProbeCache($cache, $locker);

        $probe = new FixtureProbe(600);
        $target = self::target('example.com');
        $key = ProbeCache::cacheKey($probe, $target, new ProbeOptions());
        $cache->put($key, '{broken json', 600);

        $result = $probeCache->getOrSet($probe, $target, new ProbeOptions(), fn (): ProbeResult => new ProbeResult('fixture', 0, 5, [], ['ok' => true]));

        self::assertTrue($result->payload['ok']);
    }

    public function test_json_round_trip_is_lossless(): void
    {
        $result = new ProbeResult(
            probe: 'whois',
            fetchedAt: 1755500000,
            latencyMs: 812,
            degradedSources: ['crt.sh', 'certspotter'],
            payload: ['domain' => 'сайт.рф', 'expires_in_days' => 8, 'nested' => ['a' => 1, 'b' => 'x']],
        );

        $restored = ProbeResult::fromArray(json_decode(json_encode($result->toArray(), JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR));

        self::assertSame($result->toArray(), $restored->toArray());
    }

    public function test_semaphore_serializes_heavy_probes(): void
    {
        $locker = new FakeLocker();
        $first = new ProbeSemaphore($locker);
        $second = new ProbeSemaphore($locker);

        $first->acquire(10);

        try {
            $second->acquire(10);
            self::fail('expected SemaphoreBusyException');
        } catch (SemaphoreBusyException $exception) {
            self::assertSame(15, $exception->messageParams['retry_in_seconds']);
            self::assertStringContainsString('~15s', $exception->userMessage());
        }

        $first->release();
        $second->acquire(10);
        $second->release();

        $third = new ProbeSemaphore($locker);
        $third->acquire(10);
        $third->release();
    }

    /** @return array{OutboundCacheContract, FakeLocker} */
    private function primitives(): array
    {
        return [FakeOutboundCacheFactory::create(), new FakeLocker()];
    }

    private static function target(string $host): NetTarget
    {
        return new NetTarget($host, $host, ['93.184.216.34'], true, false, GuardVerdict::allow());
    }
}
