<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Contracts\Exceptions;

final class QuotaExceededException extends NettoolsException
{
    public function __construct(int $used, int $max, int $resetInMinutes)
    {
        parent::__construct('quota_exceeded', [
            'used' => $used,
            'max' => $max,
            'reset_in_minutes' => $resetInMinutes,
        ], "quota exceeded: {$used}/{$max}, resets in {$resetInMinutes}m");
    }
}
