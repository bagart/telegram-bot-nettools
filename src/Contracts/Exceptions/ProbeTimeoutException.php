<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Contracts\Exceptions;

final class ProbeTimeoutException extends NettoolsException
{
    public function __construct(string $probe, int $seconds, ?string $step = null)
    {
        parent::__construct('probe_timeout', [
            'probe' => $probe,
            'seconds' => $seconds,
            'step' => $step ?? '?',
        ], "probe {$probe} timed out after {$seconds}s".($step !== null ? " at {$step}" : ''));
    }
}
