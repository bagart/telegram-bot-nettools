<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Contracts\Exceptions;

final class NxDomainException extends NettoolsException
{
    public function __construct(string $host, string $detail = '')
    {
        parent::__construct('nxdomain', ['host' => $host], $detail !== '' ? $detail : "NXDOMAIN: {$host}");
    }
}
