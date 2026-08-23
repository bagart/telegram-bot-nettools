<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Contracts\Exceptions;

final class SemaphoreBusyException extends NettoolsException
{
    public function __construct(int $retryInSeconds)
    {
        parent::__construct('semaphore_busy', ['retry_in_seconds' => $retryInSeconds], "heavy probe contended, retry in ~{$retryInSeconds}s");
    }
}
