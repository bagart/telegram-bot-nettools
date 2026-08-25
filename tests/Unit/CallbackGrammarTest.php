<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Unit;

use BAGArt\TelegramBotNettools\Ui\CallbackGrammar;
use BAGArt\TelegramBotNettools\Ui\Keyboards\MainMenuKb;
use BAGArt\TelegramBotNettools\Ui\Keyboards\MenuBackRow;
use BAGArt\TelegramBotNettools\Ui\NtCards;
use PHPUnit\Framework\TestCase;

/**
 * Telegram hard budget: every produced callback_data ≤64 bytes (RFC D7),
 * enforced over every keyboard builder.
 */
final class CallbackGrammarTest extends TestCase
{
    public function test_round_trip(): void
    {
        $data = CallbackGrammar::encode('help', -100200);

        self::assertSame('nt:v1:help:-100200', $data);

        $route = CallbackGrammar::decode($data);
        self::assertSame(['action' => 'help', 'chatId' => -100200, 'ref' => ''], $route);
    }

    public function test_ref_round_trip(): void
    {
        $route = CallbackGrammar::decode(CallbackGrammar::encode('subs', 42, 'h0a1b2c3'));

        self::assertSame('subs', $route['action']);
        self::assertSame(42, $route['chatId']);
        self::assertSame('h0a1b2c3', $route['ref']);
    }

    public function test_rejects_foreign_and_malformed_data(): void
    {
        foreach ([null, '', 'sm:1:m', 'nt:v2:menu:1', 'nt:v1:', 'nt:v1:menu:notachat', 'nt:v1::5'] as $data) {
            self::assertNull(CallbackGrammar::decode($data), 'expected null for '.var_export($data, true));
        }
    }

    public function test_encode_enforces_64_byte_budget(): void
    {
        $this->expectException(\LogicException::class);
        CallbackGrammar::encode('menu', 1, str_repeat('x', 64));
    }

    public function test_encode_validates_action_charset(): void
    {
        $this->expectException(\LogicException::class);
        CallbackGrammar::encode('BAD ACTION;drop', 1);
    }

    public function test_every_keyboard_button_fits_budget(): void
    {
        $chatIds = [1, 42, -100200300, PHP_INT_MAX];

        foreach ($chatIds as $chatId) {
            foreach (MainMenuKb::rows($chatId) as $row) {
                foreach ($row as $button) {
                    self::assertLessThanOrEqual(
                        CallbackGrammar::MAX_BYTES,
                        strlen($button->callbackData),
                        "keyboard button overflow for chatId {$chatId}",
                    );
                }
            }
            foreach (MenuBackRow::row($chatId) as $button) {
                self::assertLessThanOrEqual(CallbackGrammar::MAX_BYTES, strlen($button->callbackData));
            }
        }
    }

    public function test_cards_produce_text_and_keyboard(): void
    {
        $menu = NtCards::mainMenu(7, '0.1.0', ['ping: ✅']);

        self::assertStringContainsString('NETTOOLS · v', $menu['text']);
        self::assertCount(3, $menu['keyboard']);
        self::assertSame('🎯 My targets', $menu['keyboard'][0][0]->text);

        $help = NtCards::help(7);

        self::assertStringContainsString('/quota — remaining budget in this chat', $help['text']);
        self::assertStringContainsString('/whois — registrar, dates, statuses <i>(2)</i>', $help['text'], 'shipped commands render without the construction glyph');
        self::assertStringContainsString('/subs — subdomain enumeration <i>(3)</i>', $help['text'], 'shipped commands render without the construction glyph');
        self::assertStringContainsString('🚧 /portscan', $help['text'], 'admin-gated tools stay on the roadmap section');
        self::assertCount(1, $help['keyboard']);

        foreach ([$menu['keyboard'], $help['keyboard']] as $kb) {
            foreach ($kb as $row) {
                foreach ($row as $button) {
                    self::assertLessThanOrEqual(CallbackGrammar::MAX_BYTES, strlen($button->callbackData));
                }
            }
        }
    }
}
