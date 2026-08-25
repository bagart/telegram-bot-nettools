<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Ui;

/**
 * Single inline-button descriptor. Pure data — no Telegram SDK types here;
 * processors map rows of buttons to InlineKeyboardMarkupTypeDTO.
 */
final readonly class Button
{
    public function __construct(
        public string $text,
        public string $callbackData,
    ) {
    }

    /**
     * @param  list<list<Button>>  $rows
     * @return list<list<array{text: string, callback_data: string}>>
     */
    public static function toCallbackRows(array $rows): array
    {
        $mapped = [];
        foreach ($rows as $row) {
            $mappedRow = [];
            foreach ($row as $button) {
                $mappedRow[] = ['text' => $button->text, 'callback_data' => $button->callbackData];
            }
            $mapped[] = $mappedRow;
        }

        return $mapped;
    }
}
