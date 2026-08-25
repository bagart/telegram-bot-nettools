<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Commands;

use BAGArt\TelegramBot\Modules\Attributes\TgCommandAttribute;
use BAGArt\TelegramBotNettools\NettoolsSettings;
use BAGArt\TelegramBotNettools\Probes\SslProbe;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Ui\SslCard;

/**
 * /ssl <target> (RFC §7.7): full certificate audit — validity countdown,
 * key/sig strength, hostname semantics, chain, offered protocol versions.
 * Weight 2 (four extra protocol-probing handshakes).
 */
#[TgCommandAttribute(name: 'ssl')]
final class SslCommand extends ProbeCommand
{
    public const string NAME = 'ssl';

    public const int WEIGHT = 2;

    protected function featureEnabled(NettoolsSettings $settings): bool
    {
        return $settings->auditEnabled;
    }

    protected function probeFor(NetTarget $target): array
    {
        return [
            new SslProbe(SslProbe::selfInspector()),
            new ProbeOptions(timeoutSeconds: $this->effSettings->timeoutHttpFetch),
        ];
    }

    protected function renderCard(ProbeResult $result, int $chatId, string $hostLabel): array
    {
        return SslCard::render($result, $chatId, time(), $hostLabel);
    }
}
