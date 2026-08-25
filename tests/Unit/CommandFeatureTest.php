<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Unit;

use BAGArt\TelegramBotNettools\Commands\IpCommand;
use BAGArt\TelegramBotNettools\Commands\NtCallbackRouter;
use BAGArt\TelegramBotNettools\Commands\PortCommand;
use BAGArt\TelegramBotNettools\Tests\Support\FakeBotHarness;
use BAGArt\TelegramBotNettools\Ui\CallbackGrammar;

/**
 * Feature layer (RFC §12): real processors over the FakeBotHarness — usage
 * cards, happy paths, quota charging, /r bookkeeping, heavy-confirm loop.
 */
final class CommandFeatureTest extends \PHPUnit\Framework\TestCase
{
    public function test_usage_card_on_missing_target_costs_nothing(): void
    {
        $harness = FakeBotHarness::create();
        $cmd = new IpCommand($harness->sender, $harness->services, $harness->context);

        $cmd->process($harness->message('/ip'), $harness->botConfig());

        self::assertStringContainsString('Usage: /ip', $harness->lastText());
        self::assertSame(0, $harness->services->quota->usedByUser(100, 42));
    }

    public function test_ip_happy_path_renders_card_and_charges_quota(): void
    {
        $harness = FakeBotHarness::create([
            'http://ip-api.com/json/93.184.216.34?fields=status,message,country,regionName,city,lat,lon,isp,org,as,asname,mobile,proxy,hosting,query' => [
                'status' => 'success', 'country' => 'United States', 'city' => 'Norwell',
                'lat' => 42.15, 'lon' => -70.82, 'as' => 'AS15169 GOOGLE', 'org' => 'Google LLC',
                'reverse' => 'edge.example.net',
            ],
        ]);
        $cmd = new IpCommand($harness->sender, $harness->services, $harness->context);

        $cmd->execute($harness->botConfig(), '100', 42, '93.184.216.34');

        $text = $harness->lastText();
        self::assertStringContainsString('IP · 93.184.216.34', $text);
        self::assertStringContainsString('AS15169', $text);
        self::assertSame(1, $harness->services->quota->usedByUser(100, 42));

        // last-action recorded for /r
        $last = $harness->services->lastAction()->recall('100');
        self::assertSame('ip', $last['command']);
        self::assertSame('93.184.216.34', $last['args']);
    }

    public function test_feature_disabled_shows_error_not_charge(): void
    {
        $harness = FakeBotHarness::create([], ['features' => ['recon' => false]]);
        $cmd = new IpCommand($harness->sender, $harness->services, $harness->context);

        $cmd->execute($harness->botConfig(), '100', 42, '93.184.216.34');

        self::assertStringContainsStringIgnoringCase('disabled', $harness->lastText());
        self::assertSame(0, $harness->services->quota->usedByUser(100, 42));
    }

    public function test_port_command_rate_limit_and_invalid_port(): void
    {
        $harness = FakeBotHarness::create();
        $cmd = new PortCommand($harness->sender, $harness->services, $harness->context);

        $cmd->execute($harness->botConfig(), '100', 42, 'example.org notaport');
        self::assertStringContainsString('Invalid port', $harness->lastText());

        for ($i = 0; $i < 20; $i++) {
            $probe = new PortCommand($harness->sender, $harness->services, $harness->context);
            // connector attempts fail fast against unroutable port; ignore result
            @$probe->execute($harness->botConfig(), '100', 42, '192.0.2.55 9');
        }
        $limiter = new PortCommand($harness->sender, $harness->services, $harness->context);
        $limiter->execute($harness->botConfig(), '100', 42, '192.0.2.55 80');

        self::assertStringContainsString('limit reached', $harness->lastText());
    }

    public function test_repeat_empty_state(): void
    {
        $harness = FakeBotHarness::create();
        $r = new \BAGArt\TelegramBotNettools\Commands\RepeatCommand($harness->sender, $harness->services, $harness->context);

        $r->process($harness->message('/r'), $harness->botConfig());

        self::assertStringContainsString('Nothing to repeat', $harness->lastText());
    }

    public function test_trace_heavy_confirm_flow_via_callback(): void
    {
        $harness = FakeBotHarness::create();
        $trace = new \BAGArt\TelegramBotNettools\Commands\TraceCommand($harness->sender, $harness->services, $harness->context);

        $trace->execute($harness->botConfig(), '100', 42, '93.184.216.34');

        $confirm = $harness->lastText();
        self::assertStringContainsString('heavier operation', $confirm);

        // nothing charged until confirmed
        self::assertSame(0, $harness->services->quota->usedByUser(100, 42));

        $ref = null;
        foreach ($harness->sender->keyboards() as [, $rows]) {
            foreach ($rows as $row) {
                foreach ($row as $button) {
                    if (($button['callback_data'] ?? null) !== null && str_contains((string) $button['callback_data'], ':go:')) {
                        $ref = $button['callback_data'];
                    }
                }
            }
        }
        self::assertNotNull($ref, 'confirm card must offer a :go: button');

        $router = new NtCallbackRouter($harness->sender, $harness->services, $harness->context);
        $router->process($harness->callback($ref), $harness->botConfig());

        self::assertSame(4, $harness->services->quota->usedByUser(100, 42), '/trace weight 4 charged after confirm');
        self::assertCount(1, $harness->sender->answers());
    }

    public function test_callback_cancel_answers_and_clears_form(): void
    {
        $harness = FakeBotHarness::create();
        $harness->services->formState()->set('100', 42, ['flow' => 'confirm', 'step' => 'run']);

        $router = new NtCallbackRouter($harness->sender, $harness->services, $harness->context);
        $router->process(
            $harness->callback(CallbackGrammar::encode('cancel', 100)),
            $harness->botConfig(),
        );

        self::assertNull($harness->services->formState()->get('100', 42));
        self::assertCount(1, $harness->sender->answers());
    }
}

/** ip-api fields query string (mirrors IpApiSource::FIELDS). */
final class IpApiFields
{
    public const string STRING = 'status,country,regionName,city,lat,lon,as,org,reverse';
}
