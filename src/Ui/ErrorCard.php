<?php

namespace BAGArt\TelegramBotNettools\Ui;

use BAGArt\TelegramBotNettools\Contracts\Exceptions\NettoolsException;
use BAGArt\TelegramBotNettools\Formatting\Messages;
use BAGArt\TelegramBotNettools\Ui\Keyboards\MenuBackRow;

/**
 * Typed-exception → user card mapping (RFC §4.6). Every failure screen keeps
 * an escape route (menu row) — no dead ends (§3.9).
 *
 * @return array{text: string, keyboard: list<list<Button>>}
 */
final class ErrorCard
{
    public static function fromException(\Throwable $exception, int $chatId): array
    {
        $text = $exception instanceof NettoolsException
            ? $exception->userMessage()
            : Messages::format('unexpected_error');

        return ['text' => $text, 'keyboard' => [MenuBackRow::row($chatId)]];
    }
}
