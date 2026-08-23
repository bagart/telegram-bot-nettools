<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Contracts\Exceptions;

final class TargetBlockedException extends NettoolsException
{
    public function __construct(string $reason, string $detail = '')
    {
        parent::__construct('target_blocked', ['reason' => $reason], $detail !== '' ? $detail : "blocked: {$reason}");
    }
}
