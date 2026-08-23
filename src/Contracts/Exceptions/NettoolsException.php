<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Contracts\Exceptions;

use BAGArt\TelegramBotNettools\Formatting\Messages;

/**
 * Base of the nettools error taxonomy (RFC §4.6). Every subclass maps 1:1 to
 * a user-facing message template in the i18n catalog.
 */
abstract class NettoolsException extends \RuntimeException
{
    /**
     * @param  string  $detail  technical detail for logs; the user sees the
     *                          rendered {@see $messageKey} template instead
     * @param  array<string, string|int>  $messageParams
     */
    public function __construct(
        public readonly string $messageKey,
        public readonly array $messageParams = [],
        string $detail = '',
    ) {
        parent::__construct($detail !== '' ? $detail : $messageKey);
    }

    public function userMessage(): string
    {
        return Messages::format($this->messageKey, $this->messageParams);
    }
}
