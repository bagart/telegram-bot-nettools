<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Ui;

use BAGArt\TelegramBotNettools\Support\QuotaLedger;

/**
 * Pure /quota screen.
 */
final class QuotaCard
{
    /**
     * @return array{text: string, keyboard: list<list<Button>>}
     */
    public static function render(QuotaLedger $ledger, int|string $chatId, int|string|null $userId): array
    {
        if ($ledger->isAdminChat($chatId)) {
            return [
                'text' => "<b>QUOTA</b>\n👑 Admin chat — quotas bypassed.",
                'keyboard' => [],
            ];
        }

        $used = $userId !== null ? $ledger->usedByUser($chatId, $userId) : 0;
        $limit = $ledger->limitFor($chatId);
        $chatUsed = $ledger->usedInChat($chatId);
        $resetIn = QuotaCard::humanizeMinutes($ledger->resetsInMinutes($chatId, $userId));

        $lines = ['<b>QUOTA</b>'];
        if ($userId !== null) {
            $lines[] = sprintf('You: %d / %d units today', min($used, $limit), $limit);
        }
        $lines[] = sprintf('Chat pool: %d / %d units today', min($chatUsed, $ledger->ceiling()), $ledger->ceiling());
        $lines[] = 'Resets in ~'.$resetIn;
        $lines[] = '';
        $lines[] = '<i>Weights: /nt help</i>';

        return [
            'text' => implode("\n", $lines),
            'keyboard' => [],
        ];
    }

    private static function humanizeMinutes(int $minutes): string
    {
        if ($minutes < 60) {
            return "{$minutes}m";
        }

        return sprintf('%dh %02dm', intdiv($minutes, 60), $minutes % 60);
    }
}
