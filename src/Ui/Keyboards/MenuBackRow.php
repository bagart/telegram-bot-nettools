<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Ui\Keyboards;

use BAGArt\TelegramBotNettools\Ui\Button;
use BAGArt\TelegramBotNettools\Ui\CallbackGrammar;

final class MenuBackRow
{
    /**
     * @return list<Button>
     */
    public static function row(int $chatId): array
    {
        return [new Button('⬅ Menu', CallbackGrammar::encode('menu', $chatId))];
    }
}
