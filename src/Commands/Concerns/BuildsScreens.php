<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Commands\Concerns;

use BAGArt\TelegramBotNettools\NettoolsModule;
use BAGArt\TelegramBotNettools\NettoolsServices;
use BAGArt\TelegramBotNettools\Ui\Button;
use BAGArt\TelegramBotNettools\Ui\NtCards;

/**
 * Shared /nt screen builders for the command and the callback router.
 *
 * @phpstan-require-property NettoolsServices $services
 */
trait BuildsScreens
{
    /** @return array{text: string, keyboard: list<list<Button>>} */
    private function menuCard(int $chatId): array
    {
        return NtCards::mainMenu(
            chatId: $chatId,
            version: NettoolsModule::VERSION,
            capabilityLines: $this->services->capabilities->summaryLines(),
        );
    }

    /** @return array{text: string, keyboard: list<list<Button>>} */
    private function helpCard(int $chatId): array
    {
        return NtCards::help($chatId);
    }
}
