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
            'reset_in' => self::humanizeMinutes($resetInMinutes),
        ], "quota exceeded: {$used}/{$max}, resets in {$resetInMinutes}m");
    }

    private static function humanizeMinutes(int $minutes): string
    {
        if ($minutes < 60) {
            return "{$minutes}m";
        }

        return sprintf('%dh %02dm', intdiv($minutes, 60), $minutes % 60);
    }
}
