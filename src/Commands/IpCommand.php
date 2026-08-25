<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Commands;

use BAGArt\TelegramBot\Modules\Attributes\TgCommandAttribute;
use BAGArt\TelegramBotNettools\NettoolsSettings;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Ui\IpCard;

/**
 * /ip <target> (RFC §7.3): geo, ASN + owner + type classification, rDNS with
 * forward confirmation, dual-stack note. Weight 1. Alias: /geo.
 */
#[TgCommandAttribute(name: 'ip')]
class IpCommand extends ProbeCommand
{
    public const string NAME = 'ip';

    protected static function aliases(): array
    {
        return ['geo'];
    }

    protected function featureEnabled(NettoolsSettings $settings): bool
    {
        return $settings->reconEnabled;
    }

    protected function probeFor(NetTarget $target): array
    {
        return [
            $this->services->geoProbe(),
            new ProbeOptions(timeoutSeconds: 3),
        ];
    }

    protected function renderCard(ProbeResult $result, int $chatId, string $hostLabel): array
    {
        return IpCard::render($result, $chatId, time(), $hostLabel);
    }
}
