<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Commands;

use BAGArt\TelegramBot\Modules\Attributes\TgCommandAttribute;

/**
 * /geo — thin alias of /ip (RFC §3.1). Reuses every behavior of IpCommand.
 */
#[TgCommandAttribute(name: 'geo')]
final class GeoCommand extends IpCommand
{
    public const string NAME = 'geo';

    protected static function aliases(): array
    {
        return [];
    }
}
