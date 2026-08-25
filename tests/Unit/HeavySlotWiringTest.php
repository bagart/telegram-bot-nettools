<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Unit;

use BAGArt\TelegramBotNettools\Commands\NtCallbackRouter;
use BAGArt\TelegramBotNettools\Commands\PortscanCommand;
use BAGArt\TelegramBotNettools\Commands\ReportCommand;
use BAGArt\TelegramBotNettools\Commands\TraceCommand;
use BAGArt\TelegramBotNettools\NettoolsServices;
use BAGArt\TelegramBotNettools\NettoolsSettings;
use BAGArt\TelegramBotNettools\Probes\PortScanProbe;
use BAGArt\TelegramBotNettools\Support\ProbeSemaphore;
use BAGArt\TelegramBotNettools\Support\QuotaLedger;
use BAGArt\TelegramBotNettools\Tests\Support\FakeBotHarness;
use BAGArt\TelegramBotNettools\Tests\Support\FakeDnsTransport;
use BAGArt\TelegramBotNettools\Tests\Support\FakeHttpSource;
use BAGArt\TelegramBotNettools\Tests\Support\FakeProbeFetcher;
use BAGArt\TelegramBotNettools\Tests\Support\FakePort43Transport;
use BAGArt\TelegramBotNettools\Ui\CallbackGrammar;
use PHPUnit\Framework\TestCase;

/**
 * Heavy-slot wiring (todo.nettools P0-4 gate): heavy commands hold the
 * global semaphore; a busy rejection renders the friendly card, charges no
 * quota, consumes no rate slot — and the slot is released after a run.
 */
final class HeavySlotWiringTest extends TestCase
{
    private const string HEAVY_KEY = 'tg-nettools:heavy';

    public function test_busy_semaphore_blocks_trace_without_charging_quota(): void
    {
        $harness = FakeBotHarness::create();
        (new ProbeSemaphore($harness->services->locker))->acquire(15);

        (new TraceCommand($harness->sender, $harness->services, $harness->context))
            ->execute($harness->botConfig(), '100', 42, '93.184.216.34', confirmed: true);

        self::assertStringContainsString('heavy probe is running', $harness->lastText());
        self::assertSame(0, $harness->services->quota->usedByUser(100, 42), 'busy rejection must not consume quota');
        self::assertSame(1, $harness->services->metrics()->counter('semaphore_busy', 'events'));
        self::assertTrue($harness->services->locker->isLocked(self::HEAVY_KEY), 'foreign lock must survive');
    }

    public function test_busy_semaphore_blocks_report_without_charging_quota(): void
    {
        $harness = FakeBotHarness::create();
        (new ProbeSemaphore($harness->services->locker))->acquire(ReportCommand::HEAVY_CAP_SECONDS);

        (new ReportCommand($harness->sender, $harness->services, $harness->context))
            ->execute($harness->botConfig(), '100', 42, '93.184.216.34', confirmed: true);

        self::assertStringContainsString('heavy probe is running', $harness->lastText());
        self::assertSame(0, $harness->services->quota->usedByUser(100, 42));
    }

    public function test_busy_semaphore_blocks_portscan_without_charging_quota(): void
    {
        $harness = FakeBotHarness::create();
        $services = $this->adminServicesForPortscan($harness);
        (new ProbeSemaphore($services->locker))->acquire(PortScanProbe::WALL_CAP_SECONDS);

        (new PortscanCommand($harness->sender, $services, $harness->context))
            ->execute($harness->botConfig(), '100', 42, '93.184.216.34', confirmed: true);

        self::assertStringContainsString('heavy probe is running', $harness->lastText());
        self::assertSame(0, $services->quota->usedByUser(100, 42));
    }

    public function test_world_ping_holds_and_releases_the_heavy_slot(): void
    {
        $harness = FakeBotHarness::create([
            // FakeProbeFetcher matches requested URLs with query strings stripped.
            'raw:https://check-host.net/check/ping' => '{"request_id":"abc","nodes":{"1.2.3.4":["RU","Moscow"]}}',
            'raw:https://check-host.net/check-result/abc' => '{"1.2.3.4":[[0.05,"1.2.3.4",null]]}',
        ]);
        $ref = $harness->services->targetRef()->remember('93.184.216.34', 'ping_world');

        $this->router($harness)->process(
            $harness->callback(CallbackGrammar::encode('wping', 100, $ref)),
            $harness->botConfig(),
        );

        self::assertStringContainsString('WORLD PING', $harness->lastText());
        self::assertSame(1, $harness->services->metrics()->counter('heavy_acquired', 'events'));
        self::assertFalse($harness->services->locker->isLocked(self::HEAVY_KEY), 'slot must be released after the run');
    }

    public function test_busy_world_ping_answers_without_consuming_the_rate_slot(): void
    {
        $harness = FakeBotHarness::create();
        (new ProbeSemaphore($harness->services->locker))->acquire(35);
        $ref = $harness->services->targetRef()->remember('93.184.216.34', 'ping_world');

        $this->router($harness)->process(
            $harness->callback(CallbackGrammar::encode('wping', 100, $ref)),
            $harness->botConfig(),
        );

        self::assertStringContainsString('heavy probe is running', (string) ($harness->sender->answers()[0]?->text ?? ''));
        self::assertTrue(
            $harness->services->rateLimiter()->hit('worldping', '100', 42, 1, 60),
            'busy rejection must not consume the once-per-minute budget',
        );
        self::assertSame(0, $harness->services->metrics()->counter('heavy_acquired', 'events'));
    }

    /**
     * /portscan needs the admin-chat quota ledger + enabled feature flag to
     * pass its own deny gate and reach the semaphore path.
     */
    private function adminServicesForPortscan(FakeBotHarness $harness): NettoolsServices
    {
        $s = $harness->services;

        return new NettoolsServices(
            cache: $s->cache,
            locker: $s->locker,
            http: new FakeHttpSource(),
            quota: new QuotaLedger($s->cache, adminChatIds: ['100']),
            semaphore: $s->semaphore,
            probeCache: $s->probeCache,
            capabilities: $s->capabilities,
            targets: $s->targets,
            settings: NettoolsSettings::fromArray(['features' => ['portscan' => true]]),
            fetcher: new FakeProbeFetcher(),
            dnsTransport: new FakeDnsTransport(),
            port43: new FakePort43Transport(null),
            mmdb: null,
            breaker: $s->breaker,
            logger: $s->logger,
            targetRepo: $s->targetRepo,
        );
    }

    private function router(FakeBotHarness $harness): NtCallbackRouter
    {
        return new NtCallbackRouter($harness->sender, $harness->services, $harness->context);
    }
}
