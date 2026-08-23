<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Contracts\Exceptions;

final class CapabilityMissingException extends NettoolsException
{
    public function __construct(string $capability)
    {
        parent::__construct('capability_missing', ['capability' => $capability], "capability missing: {$capability}");
    }
}
