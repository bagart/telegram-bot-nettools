<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Support;

/**
 * Short, user-safe error labels for degraded/failed report sections —
 * never raw exception messages (they may carry upstream URLs).
 */
final class ErrorLabel
{
    public static function of(\Throwable $exception): string
    {
        return match (true) {
            $exception instanceof \BAGArt\TelegramBotNettools\Contracts\Exceptions\NxDomainException => 'nxdomain',
            $exception instanceof \BAGArt\TelegramBotNettools\Contracts\Exceptions\TargetBlockedException => 'blocked',
            $exception instanceof \BAGArt\TelegramBotNettools\Contracts\Exceptions\InvalidTargetException => 'invalid',
            $exception instanceof \BAGArt\TelegramBotNettools\Contracts\Exceptions\UpstreamUnavailableException => 'unavailable',
            $exception instanceof \BAGArt\TelegramBotNettools\Contracts\Exceptions\ProbeTimeoutException => 'timeout',
            default => 'error',
        };
    }
}
