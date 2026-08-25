<?php

declare(strict_types=1);

namespace BAGArt\TelegramBotNettools\Commands;

use BAGArt\TelegramBot\Modules\Attributes\TgCommandAttribute;
use BAGArt\TelegramBotNettools\NettoolsSettings;
use BAGArt\TelegramBotNettools\Results\NetTarget;
use BAGArt\TelegramBotNettools\Results\ProbeOptions;
use BAGArt\TelegramBotNettools\Results\ProbeResult;
use BAGArt\TelegramBotNettools\Ui\WhoisCard;

/**
 * /whois <domain|IP> (RFC §7.1): RDAP → port-43 fallback; registrar, dates
 * with age/expiry countdown, statuses, nameservers, redaction-aware
 * contacts, DNSSEC flag, homograph hint, availability hint. Weight 2.
 */
#[TgCommandAttribute(name: 'whois')]
final class WhoisCommand extends ProbeCommand
{
    public const string NAME = 'whois';

    public const int WEIGHT = 2;

    protected function featureEnabled(NettoolsSettings $settings): bool
    {
        return $settings->reconEnabled;
    }

    protected function probeFor(NetTarget $target): array
    {
        return [
            $this->services->whoisProbe(),
            new ProbeOptions(timeoutSeconds: $this->effSettings->timeoutWhois43),
        ];
    }

    protected function renderCard(ProbeResult $result, int $chatId, string $hostLabel): array
    {
        return WhoisCard::render($result, $chatId, time(), $hostLabel);
    }
}
