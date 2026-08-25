<?php

namespace BAGArt\TelegramBotNettools\Ui\Keyboards;

use BAGArt\TelegramBotNettools\Ui\Button;
use BAGArt\TelegramBotNettools\Ui\CallbackGrammar;

/**
 * Pure target-context keyboard (RFC §3.5): habit-ranked probe buttons
 * (pre-encoded by the caller through TargetRef), pin/forget service row.
 * ≤3 buttons per row.
 */
final class TargetContextKb
{
    /**
     * @param  list<array{label: string, data: string}>  $probeButtons
     */
    public static function rows(int $chatId, array $probeButtons, string $hostRef, bool $pinned): array
    {
        $rows = [];
        foreach (array_chunk(array_slice($probeButtons, 0, 9), 3) as $chunk) {
            $rows[] = array_map(static fn (array $button): Button => new Button(
                strtoupper((string) $button['label']),
                (string) $button['data'],
            ), $chunk);
        }

        $rows[] = [
            new Button($pinned ? '☆ Unpin' : '⭐ Pin', CallbackGrammar::encode($pinned ? 'unpin' : 'pin', $chatId, $hostRef)),
            new Button('🗑 Forget', CallbackGrammar::encode('forget', $chatId, $hostRef)),
            new Button('« Menu', CallbackGrammar::encode('menu', $chatId)),
        ];

        return $rows;
    }
}
