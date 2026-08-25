<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Unit;

use BAGArt\TelegramBotNettools\Commands\TraceCommand;
use BAGArt\TelegramBotNettools\NettoolsServices;
use BAGArt\TelegramBotNettools\Probes\TraceProbe;
use BAGArt\TelegramBotNettools\Results\GuardVerdict;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Support\CapabilityDetector;
use BAGArt\TelegramBotNettools\Tests\Support\FakeBotHarness;
use BAGArt\TelegramBotNettools\Tests\Support\FakeOutboundCacheFactory;
use PHPUnit\Framework\TestCase;

/**
 * Progressive /trace (§7.5): parsed hops stream out via the onHop hook while
 * the run is in flight, and TraceCommand turns them into sendMessageDraft
 * previews before the final card persists.
 */
final class TraceProgressiveTest extends TestCase
{
    private const string TRACE_OUT = <<<'OUT'
        traceroute to 93.184.216.34 (93.184.216.34), 15 hops max, 60 byte packets
         1  10.0.0.1  1.240 ms
         2  172.16.0.9  4.811 ms
         3  * * *
         4  93.184.216.34  12.003 ms
        OUT;

    public function test_probe_streams_parsed_hops_via_callback(): void
    {
        $streamed = [];
        $probe = new TraceProbe(
            capabilities: new CapabilityDetector(FakeOutboundCacheFactory::create()),
            maxHops: 15,
            onHop: function (array $hop) use (&$streamed): void {
                $streamed[] = $hop;
            },
            runStreaming: function (array $argv, \Closure $emit): array {
                foreach (explode("\n", self::TRACE_OUT) as $line) {
                    $emit($line);
                }

                return ['exit' => 0, 'out' => self::TRACE_OUT];
            },
        );

        $result = $probe->probe(new NetTarget('example.com', 'example.com', ['93.184.216.34'], true, false, GuardVerdict::allow()), new ProbeOptions());

        self::assertCount(4, $streamed, 'every hop line must be streamed');
        self::assertSame(['n' => 1, 'ip' => '10.0.0.1', 'ms' => [1.24], 'timeout' => false], $streamed[0]);
        self::assertSame(['n' => 3, 'ip' => null, 'ms' => [], 'timeout' => true], $streamed[2]);

        // The final payload stays complete and independent of streaming
        self::assertSame(4, $result->payload['hop_count']);
        self::assertTrue($result->payload['reached']);
    }

    public function test_bulk_fake_runner_replays_hops_to_hook(): void
    {
        $streamed = [];
        $probe = new TraceProbe(
            capabilities: new CapabilityDetector(FakeOutboundCacheFactory::create()),
            onHop: function (array $hop) use (&$streamed): void {
                $streamed[] = $hop['n'];
            },
            runProcess: static fn (): array => ['exit' => 0, 'out' => self::TRACE_OUT],
        );

        $probe->probe(new NetTarget('example.com', 'example.com', ['93.184.216.34'], true, false, GuardVerdict::allow()), new ProbeOptions());

        self::assertSame([1, 2, 3, 4], $streamed);
    }

    public function test_command_sends_draft_previews_then_final_card(): void
    {
        $harness = FakeBotHarness::create();
        $harness->services = NettoolsServices::forTests(
            $harness->services->cache,
            $harness->services->locker,
            $harness->services->http,
            fetcher: $harness->services->fetcher,
            traceFakeRun: static fn (): array => ['exit' => 0, 'out' => self::TRACE_OUT],
        );

        $sender = $harness->sender;
        $trace = new TraceCommand($sender, $harness->services, $harness->context);

        // IP literal: skips the resolver pipeline (unit env has no real DNS)
        $trace->execute($harness->botConfig(), '100', 42, '93.184.216.34', confirmed: true);

        $drafts = $sender->drafts();
        self::assertGreaterThanOrEqual(2, count($drafts), 'placeholder + at least one throttled replay preview');
        $firstLine = preg_split('/\n/', (string) $drafts[0]->text) ?: [''];
        $firstHead = trim((string) $firstLine[0]);
        self::assertSame('TRACEROUTE 93.184.216.34', strip_tags($firstHead));
        self::assertSame($drafts[0]->draftId, end($drafts)->draftId, 'same draft id animates one preview');

        $final = $sender->lastText();
        self::assertStringContainsString('TRACE ·', $final, 'the real card must follow the draft previews');
        self::assertStringContainsString('* * *', $final);
        self::assertStringContainsString('reached', mb_strtolower($final));
    }
}
