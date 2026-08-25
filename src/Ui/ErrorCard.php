<?php

namespace BAGArt\TelegramBotNettools\Ui;

use BAGArt\TelegramBotNettools\Contracts\Exceptions\NettoolsException;
use BAGArt\TelegramBotNettools\Formatting\Messages;
use BAGArt\TelegramBotNettools\Ui\Keyboards\MenuBackRow;

/**
 * Typed-exception → user card mapping (RFC §4.6). Every failure screen keeps
 * an escape route (menu row) AND a [Retry] affordance wired to the last
 * command in the chat (§3.9 — no dead ends).
 *
 * @return array{text: string, keyboard: list<list<Button>>}
 */
final class ErrorCard
{
    public static function fromException(\Throwable $exception, int $chatId, ?string $retryCallbackData = null): array
    {
        $text = $exception instanceof NettoolsException
            ? $exception->userMessage()
            : Messages::format('unexpected_error');

        $row = [];

        if ($retryCallbackData !== null && ! ($exception instanceof \BAGArt\TelegramBotNettools\Contracts\Exceptions\TargetBlockedException)) {
            $row[] = new Button('🔄 Retry', $retryCallbackData);
        }

        return [
            'text' => $text,
            'keyboard' => $row === [] ? [MenuBackRow::row($chatId)] : [$row, MenuBackRow::row($chatId)],
        ];
    }
}
