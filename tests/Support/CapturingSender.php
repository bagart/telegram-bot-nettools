<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Tests\Support;

use BAGArt\TelegramBot\Configs\TgBotConfig;
use BAGArt\TelegramBot\Contracts\Outbound\TgSenderContract;
use BAGArt\TelegramBot\Contracts\TgApi\TgApiMethodDTOContract;
use BAGArt\TelegramBot\TgApi\Methods\DTO\AnswerCallbackQueryMethodDTO;
use BAGArt\TelegramBot\TgApi\Methods\DTO\SendMessageMethodDTO;

/**
 * Records every outbound method DTO instead of hitting Telegram.
 */
final class CapturingSender implements TgSenderContract
{
    /** @var list<object> */
    public array $sent = [];

    public function send(TgBotConfig $botConfig, TgApiMethodDTOContract $methodDto): void
    {
        $this->sent[] = $methodDto;
    }

    /** @return list<SendMessageMethodDTO> */
    public function messages(): array
    {
        return array_values(array_filter($this->sent, static fn ($m) => $m instanceof SendMessageMethodDTO));
    }

    /** @return list<string> */
    public function texts(): array
    {
        return array_map(static fn ($m) => $m->text, $this->messages());
    }

    public function lastText(): string
    {
        foreach (array_reverse($this->sent) as $m) {
            if ($m instanceof SendMessageMethodDTO) {
                return (string) $m->text;
            }
        }

        throw new \LogicException('no message sent');
    }

    /** @return list<array{int, list<list<array{text: string, callback_data: ?string}>>}> chatId + button rows */
    public function keyboards(): array
    {
        $out = [];
        foreach ($this->messages() as $m) {
            $rows = [];
            /** @var list<list<InlineKeyboardButtonTypeShape>>|null $markup */
            $markup = $m->replyMarkup?->inlineKeyboard;
            foreach ((array) $markup as $row) {
                $buttons = [];
                foreach ($row as $b) {
                    $buttons[] = ['text' => $b->text, 'callback_data' => $b->callbackData];
                }
                $rows[] = $buttons;
            }
            $out[] = [(int) $m->chatId, $rows];
        }

        return $out;
    }

    /** @return list<AnswerCallbackQueryMethodDTO> */
    public function answers(): array
    {
        return array_values(array_filter($this->sent, static fn ($m) => $m instanceof AnswerCallbackQueryMethodDTO));
    }
}
