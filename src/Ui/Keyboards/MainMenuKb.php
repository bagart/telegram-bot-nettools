<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Ui\Keyboards;

use BAGArt\TelegramBotNettools\Ui\Button;
use BAGArt\TelegramBotNettools\Ui\CallbackGrammar;

/**
 * Pure keyboard builders (RFC §3.5): no Telegram SDK types inside, ≤3 buttons
 * per row, snapshot-tested, every callback fits the 64-byte budget.
 */
final class MainMenuKb
{
    /**
     * @return list<list<Button>>
     */
    public static function rows(int $chatId): array
    {
        return [
            [
                new Button('🎯 My targets', CallbackGrammar::encode('my', $chatId)),
                new Button('🧰 Tools', CallbackGrammar::encode('tools', $chatId)),
            ],
            [
                new Button('❓ Help', CallbackGrammar::encode('help', $chatId)),
                new Button('⚙️ Settings', CallbackGrammar::encode('settings', $chatId)),
            ],
            [
                new Button('🪙 Quota', CallbackGrammar::encode('quota', $chatId)),
            ],
        ];
    }
}
