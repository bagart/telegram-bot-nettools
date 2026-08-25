<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Commands\Concerns;

use BAGArt\TelegramBot\Configs\TgBotConfig;
use BAGArt\TelegramBot\Contracts\Outbound\TgSenderContract;
use BAGArt\TelegramBot\TgApi\Methods\DTO\SendMessageMethodDTO;
use BAGArt\TelegramBot\TgApi\Methods\Enum\ParseModeEnum;
use BAGArt\TelegramBot\TgApi\Types\DTO\InlineKeyboardButtonTypeDTO;
use BAGArt\TelegramBot\TgApi\Types\DTO\InlineKeyboardMarkupTypeDTO;
use BAGArt\TelegramBotNettools\Ui\Button;

/**
 * ack → edit → footer delivery trait (RFC §4.1): maps pure Ui\Button rows to
 * the Telegram SDK markup and sends one HTML message per card.
 *
 * @phpstan-require-property TgSenderContract $sender
 */
trait SendsCards
{
    /**
     * @param  array{text: string, keyboard: list<list<Button>>}  $card
     */
    protected function sendCard(TgBotConfig $botConfig, string $chatId, array $card): void
    {
        $rows = [];
        foreach ($card['keyboard'] as $row) {
            $buttons = [];
            foreach ($row as $button) {
                $buttons[] = new InlineKeyboardButtonTypeDTO(text: $button->text, callbackData: $button->callbackData);
            }
            $rows[] = $buttons;
        }

        $this->sender->send($botConfig, new SendMessageMethodDTO(
            chatId: $chatId,
            text: $card['text'],
            parseMode: ParseModeEnum::HTML,
            replyMarkup: $rows === [] ? null : new InlineKeyboardMarkupTypeDTO(inlineKeyboard: $rows),
        ));
    }
}
