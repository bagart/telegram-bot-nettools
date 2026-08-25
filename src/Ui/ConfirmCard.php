<?php

namespace BAGArt\TelegramBotNettools\Ui;

use BAGArt\TelegramBotNettools\Formatting\HtmlRenderer;

/**
 * Heavy-op confirmation card (RFC §3.8): cost preview + [Run]/[Cancel].
 * The Run button carries the TargetRef hash; the command itself is resolved
 * from the ref payload by the callback router.
 */
final class ConfirmCard
{
    /**
     * @return array{text: string, keyboard: list<list<Button>>}
     */
    public static function render(
        string $command,
        int $chatId,
        int $weight,
        string $host,
        string $ref,
        ?string $callbackData = null,
    ): array {
        $text = \BAGArt\TelegramBotNettools\Formatting\Messages::format('confirm_heavy', [
            'command' => '/'.$command,
            'weight' => $weight,
            'seconds' => $command === 'trace' ? 15 : 10,
            'target' => HtmlRenderer::esc($host),
        ]);

        return [
            'text' => $text,
            'keyboard' => [[
                new Button('▶ Run', $callbackData ?? CallbackGrammar::encode('go', $chatId, $ref)),
                new Button('✖ Cancel', CallbackGrammar::encode('cancel', $chatId)),
            ]],
        ];
    }
}
