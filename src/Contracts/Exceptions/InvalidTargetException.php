<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Contracts\Exceptions;

final class InvalidTargetException extends NettoolsException
{
    public function __construct(string $input, string $detail = '')
    {
        parent::__construct('invalid_target', ['input' => $input], $detail !== '' ? $detail : "invalid target: {$input}");
    }
}
