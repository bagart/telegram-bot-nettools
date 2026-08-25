<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Ui;

/**
 * Stateless callback_data grammar (RFC §3.6): `nt:v1:{action}:{chatId}[:{ref}]`.
 *
 * Hard Telegram budget: 64 bytes — enforced here at encode time and by
 * keyboard-builder unit tests. ChatId is embedded because the parsed
 * CallbackQuery DTO carries no usable originating-message payload (summarizer
 * precedent). {ref} is a numeric remembered-target id or short hash — never
 * a raw host.
 */
final class CallbackGrammar
{
    public const string VERSION = 'v1';

    public const string PREFIX = 'nt:';

    public const int MAX_BYTES = 64;

    /**
     * @throws \LogicException when the encoded data would exceed the budget
     */
    public static function encode(string $action, int $chatId, string $ref = ''): string
    {
        if (! preg_match('/^[a-z0-9_]{1,16}$/', $action)) {
            throw new \LogicException("invalid callback action: {$action}");
        }

        $data = self::PREFIX.self::VERSION.':'.$action.':'.$chatId;
        if ($ref !== '') {
            $data .= ':'.$ref;
        }

        if (strlen($data) > self::MAX_BYTES) {
            throw new \LogicException(sprintf(
                'callback_data exceeds Telegram %d-byte limit (%d bytes): %s',
                self::MAX_BYTES,
                strlen($data),
                $data,
            ));
        }

        return $data;
    }

    /**
     * null = not nettools grammar / malformed → router answers gracefully.
     *
     * @return array{action: string, chatId: int, ref: string}|null
     */
    public static function decode(?string $data): ?array
    {
        if ($data === null || ! str_starts_with($data, self::PREFIX)) {
            return null;
        }

        $parts = explode(':', substr($data, strlen(self::PREFIX)));
        if (count($parts) < 3 || count($parts) > 4 || $parts[0] !== self::VERSION) {
            return null;
        }

        $chatId = filter_var($parts[2], FILTER_VALIDATE_INT);
        if ($chatId === false || $chatId === 0 || ! preg_match('/^[a-z0-9_]{1,16}$/', $parts[1])) {
            return null;
        }

        return ['action' => $parts[1], 'chatId' => $chatId, 'ref' => $parts[3] ?? ''];
    }
}
