<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Unit;

use BAGArt\TelegramBotNettools\Contracts\Exceptions\QuotaExceededException;
use BAGArt\TelegramBotNettools\Support\QuotaLedger;
use BAGArt\TelegramBotNettools\Tests\Support\FakeOutboundCacheFactory;
use PHPUnit\Framework\TestCase;

final class QuotaLedgerTest extends TestCase
{
    public function test_charges_within_budget(): void
    {
        $ledger = new QuotaLedger(FakeOutboundCacheFactory::create(), dailyUnits: 10);

        $ledger->charge(100, 7, 4);
        $ledger->charge(100, 7, 4);

        self::assertSame(2, $ledger->remaining(100, 7));
        self::assertSame(8, $ledger->usedByUser(100, 7));
    }

    public function test_denies_when_budget_crossed_and_counter_sticks_at_limit(): void
    {
        $ledger = new QuotaLedger(FakeOutboundCacheFactory::create(), dailyUnits: 10);

        try {
            for ($i = 0; $i < 5; $i++) {
                $ledger->charge(100, 7, 3);
            }
            self::fail('expected QuotaExceededException');
        } catch (QuotaExceededException $exception) {
            self::assertSame(10, $exception->messageParams['used']);
            self::assertSame(10, $exception->messageParams['max']);
            self::assertStringContainsString('Resets in', $exception->userMessage());
        }

        // Repeated denied attempts must not inflate the counter past the limit
        self::assertSame(10, $ledger->usedByUser(100, 7));
        self::assertSame(0, $ledger->remaining(100, 7));
    }

    public function test_chat_ceiling_denies_even_with_user_budget_left(): void
    {
        $ledger = new QuotaLedger(FakeOutboundCacheFactory::create(), dailyUnits: 50, chatCeiling: 6);

        $ledger->charge(100, 1, 2);
        $ledger->charge(100, 1, 2);
        $ledger->charge(100, 2, 2);

        try {
            $ledger->charge(100, 3, 2);
            self::fail('expected QuotaExceededException');
        } catch (QuotaExceededException $exception) {
            self::assertSame(6, $exception->messageParams['max']);
            self::assertStringContainsString('/quota', $exception->userMessage());
        }
    }

    public function test_per_chat_override_raises_limit(): void
    {
        $ledger = new QuotaLedger(
            FakeOutboundCacheFactory::create(),
            dailyUnits: 5,
            chatCeiling: 150,
            chatOverrides: ['-100200' => 200],
        );

        $ledger->charge('-100200', 9, 100);

        self::assertSame(50, $ledger->remaining('-100200', 9));
        self::assertSame(200, $ledger->limitFor('-100200'));
        self::assertSame(5, $ledger->limitFor('42'));
    }

    public function test_admin_chat_bypasses_everything(): void
    {
        $ledger = new QuotaLedger(FakeOutboundCacheFactory::create(), dailyUnits: 1, adminChatIds: ['999']);

        $ledger->charge(999, 1, 500);
        $ledger->charge(999, 1, 500);

        self::assertSame(0, $ledger->usedByUser(999, 1));
        self::assertSame(0, $ledger->usedInChat(999));
    }

    public function test_zero_weight_is_free(): void
    {
        $ledger = new QuotaLedger(FakeOutboundCacheFactory::create(), dailyUnits: 1);

        $ledger->charge(1, 1, 0);
        $ledger->charge(1, 1, 0);

        self::assertSame(1, $ledger->remaining(1, 1));
    }

    public function test_reset_estimate_present(): void
    {
        $ledger = new QuotaLedger(FakeOutboundCacheFactory::create(), dailyUnits: 1);

        $ledger->charge(1, 1, 1);

        self::assertGreaterThan(0, $ledger->resetsInMinutes(1, 1));
        self::assertLessThanOrEqual(1440, $ledger->resetsInMinutes(1, 1));
    }
}
